use crate::types::CsvRecord;
use csv::Writer;
use std::fs::OpenOptions;
use std::io::BufWriter;

pub struct CsvWriter {
    writer: Writer<BufWriter<std::fs::File>>,
    done: usize,
    errors: usize,
    total: usize,
}

impl CsvWriter {
    pub fn new(path: &str, append: bool, total: usize) -> anyhow::Result<Self> {
        let file = OpenOptions::new()
            .write(true)
            .create(true)
            .append(append)
            .truncate(!append)
            .open(path)?;

        let mut writer = Writer::from_writer(BufWriter::new(file));

        if !append {
            writer.write_record(&[
                "tag",
                "proxy",
                "IP",
                "RiskScore",
                "RecentlySeen",
                "ConnectionType",
                "Proxy",
                "VPN",
                "TOR",
                "DataCenter",
                "SearchEngineBot",
                "MaskedDevices",
                "AbnormalTraffic",
                "ASN",
                "ISP",
                "Organization",
                "City",
                "Region",
                "Country",
                "CountryCode",
                "Timezone",
            ])?;
            writer.flush()?;
        }

        Ok(Self {
            writer,
            done: 0,
            errors: 0,
            total,
        })
    }

    pub fn write_record(&mut self, record: &CsvRecord) -> anyhow::Result<()> {
        self.writer.serialize(record)?;
        self.writer.flush()?;
        Ok(())
    }

    pub fn increment_done(&mut self, is_error: bool) {
        self.done += 1;
        if is_error {
            self.errors += 1;
        }
    }

    pub fn get_progress(&self) -> (usize, usize, usize) {
        (self.done, self.total, self.errors)
    }

    pub fn flush(&mut self) -> anyhow::Result<()> {
        self.writer.flush()?;
        Ok(())
    }
}
