import argparse, asyncio, csv, json, random, string, time
from datetime import timedelta
from functools import reduce
from pathlib import Path
from urllib.parse import quote as uq
import rnet

BASE, KEY = "https://ipui.fraudlogix.com", "iows8gfni4bqru7"
UA = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36"
XHR = {
  "accept": "*/*",
  "origin": "https://www.fraudlogix.com",
  "referer": "https://www.fraudlogix.com/",
  "sec-fetch-site": "same-site",
  "sec-fetch-mode": "cors",
  "sec-fetch-dest": "empty",
  "priority": "u=1, i",
}
FP = {
  "plugins": "PDF Viewer,Chrome PDF Viewer,Chromium PDF Viewer,Microsoft Edge PDF Viewer,WebKit built-in PDF",
  "mimeTypes": "application/pdf,text/pdf",
  "doNotTrack": "unknown",
  "hardwareConcurrency": 16,
  "deviceMemory": 8,
  "language": "en-US",
  "languages": "en-US,en",
}
SCREEN = {"width": 2560, "height": 1440, "colorDepth": 32, "orientation": "landscape-primary"}
FIELDS = [
  "IP", "RiskScore", "RecentlySeen", "ConnectionType",
  "Proxy", "VPN", "TOR", "DataCenter", "SearchEngineBot",
  "MaskedDevices", "AbnormalTraffic", "ASN", "ISP", "Organization",
  "City", "Region", "Country", "CountryCode", "Timezone",
]
CSV_FIELDS = ["tag", "proxy"] + FIELDS
_REQID_CHARS = string.ascii_lowercase + string.digits

jd = lambda o: json.dumps(o, separators=(",", ":"))
ri = random.randint
def fphash(data, salt): return f"fp_{reduce(lambda h, c: ((h << 5) - h + ord(c)) & 0xFFFFFFFF, data + salt, 0):08x}"
def reqid(): return "".join(random.choice(_REQID_CHARS) for _ in range(ri(11, 13)))

def _shift_ch(c, p):
  o = ord(c)
  if 48 <= o <= 57: return chr(48 + (o - 48 + p) % 10)
  if 97 <= o <= 122: return chr(97 + (o - 97 + p) % 26)
  return c

def transform(nonce, ch):
  op, p = ch["operation"], ch["parameter"]
  if op == "shift": t = "".join(_shift_ch(c, p) for c in nonce)
  elif op == "reverse": t = "".join(nonce[i : i + p][::-1] for i in range(0, len(nonce), p))
  elif op == "interleave":
    half = len(nonce) // 2
    t = "".join(c for i in range(half) for c in (nonce[i], nonce[-1 - i])) + (nonce[half] if len(nonce) % 2 else "")
  else: t = nonce
  return fphash(t, KEY)

def browser_data(nonce, tn):
  beh = {
    "mouseMovements": ri(15, 85), "keystrokes": ri(0, 4), "scrollEvents": ri(0, 8),
    "clickEvents": ri(1, 5), "touchEvents": 0, "timeOnPage": ri(2000, 8000), "focusChanges": ri(0, 3),
  }
  return jd(
    {"screen": SCREEN, "ua": UA, "h": fphash(jd({"fingerprint": FP, "behavior": beh}), tn), "n": nonce[:8] + "...", "t": int(time.time() * 1000)}
  )

async def _json(resp):
  try: return await resp.json()
  except Exception:
    txt = await resp.text()
    raise RuntimeError(f"bad response ({resp.status}): {txt[:200] if txt.strip() else 'empty'}")

async def _check(proxy_url):
  client = rnet.Client(emulation=rnet.Emulation.Chrome145, proxies=[rnet.Proxy.all(proxy_url)], cookie_store=True, timeout=timedelta(seconds=30))
  hdr = lambda extra=None: {**XHR, "x-fl-request-id": reqid(), **(extra or {})}

  resp = await client.get(f"{BASE}/get_user_ip", headers=hdr())
  ip, tok = (await _json(resp))["ip"], (resp.headers.get("x-fl-new-token") or b"").decode()

  d = await _json(await client.get(f"{BASE}/get_nonce", headers=hdr({"x-fl-auth-token": tok})))
  nonce, tn = d["nonce"], transform(d["nonce"], d["challenge"])

  return await _json(
    await client.post(
      f"{BASE}/ip_response_json",
      body=f"ip={uq(ip, safe='')}".encode(),
      headers={
        **hdr({"x-fl-auth-token": tok}),
        "content-type": "application/x-www-form-urlencoded",
        "x-fl-browser-data": browser_data(nonce, tn),
        "x-fl-nonce-id": nonce[:16],
        "x-fl-nonce-transform": tn,
      },
    )
  )

async def check_proxy(proxy_str):
  parts = proxy_str.strip().split(":")
  if len(parts) != 4: return {"proxy": proxy_str, "IP": "invalid format", "RiskScore": "ERROR"}
  h, port, u, pw = parts
  url = f"http://{uq(u, safe='')}:{uq(pw, safe='')}@{h}:{port}"
  for attempt in range(3):
    try:
      data = await _check(url)
      return {"proxy": proxy_str, **{k: data.get(k, "") for k in FIELDS}}
    except Exception as e:
      if attempt < 2: await asyncio.sleep(2.0 * (attempt + 1))
      last = e
  return {"proxy": proxy_str, "IP": str(last), "RiskScore": "ERROR"}

async def _worker(queue, tag, prog, writer, fh):
  while True:
    proxy = await queue.get()
    try:
      ret = await check_proxy(proxy)
      ret["tag"] = tag
      writer.writerow(ret); fh.flush()
      prog["done"] += 1
      err = ret.get("RiskScore") == "ERROR"
      if err: prog["errors"] += 1
      n, t = prog["done"], prog["total"]
      if err: print(f"[{n}/{t}] [ERR] {proxy} -> {ret['IP']}")
      else:
        flags = "/".join(k for k in ("Proxy", "VPN", "TOR", "DataCenter") if ret.get(k))
        print(f"[{n}/{t}] [OK] {proxy} -> {ret['IP']} | {ret.get('RiskScore', '?')}{f' [{flags}]' if flags else ''}")
    finally: queue.task_done()

async def main():
  parser = argparse.ArgumentParser()
  parser.add_argument("--tag", default="default")
  parser.add_argument("-c", "--concurrency", type=int, default=50)
  parser.add_argument("-o", "--output", default="results.csv")
  parser.add_argument("-r", "--resume", action="store_true")
  args = parser.parse_args()

  assert Path("proxies.txt").exists(), "proxies.txt not found"
  proxies = [ln.strip() for ln in Path("proxies.txt").read_text().splitlines() if ln.strip()]
  assert proxies, "proxies.txt is empty"

  out = Path(args.output)
  done = set()
  if args.resume and out.exists():
    with out.open("r", newline="") as rf: done = {r["proxy"] for r in csv.DictReader(rf)}
    proxies = [p for p in proxies if p not in done]
    print(f"Resuming: {len(done)} done, {len(proxies)} remaining")
  if not proxies: return print("All proxies already checked")

  print(f"[{args.tag}] Checking {len(proxies)} proxies (concurrency: {args.concurrency})...")
  start = time.monotonic()

  mode = "a" if done else "w"
  fh = out.open(mode, newline="")
  writer = csv.DictWriter(fh, fieldnames=CSV_FIELDS, extrasaction="ignore")
  if mode == "w": writer.writeheader(); fh.flush()

  prog = {"done": 0, "errors": 0, "total": len(proxies)}
  queue = asyncio.Queue()
  for p in proxies: queue.put_nowait(p)
  workers = [asyncio.create_task(_worker(queue, args.tag, prog, writer, fh)) for _ in range(min(args.concurrency, len(proxies)))]

  try: await queue.join()
  finally:
    for w in workers: w.cancel()
    fh.close()

  elapsed = time.monotonic() - start
  print(f"\nDone! {prog['done']} results -> {out} ({prog['errors']} errors) in {elapsed:.1f}s ({prog['done'] / max(elapsed, 0.001):.1f}/s)")

if __name__ == "__main__": asyncio.run(main())
