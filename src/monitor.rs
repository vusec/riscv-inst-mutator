use core::time::Duration;
use std::{sync::{Arc, Mutex}, borrow::BorrowMut};

use libafl::{prelude::{ClientStats, Monitor, format_duration_hms, ClientId}};
use libafl::{
    prelude::{current_time},
};

use crate::fuzz_ui::FuzzUI;


/// Tracking monitor during fuzzing.
#[derive(Clone)]
pub struct HWFuzzMonitor
{
    start_time: Duration,
    client_stats: Vec<ClientStats>,
    ui : Arc<Mutex<FuzzUI>>,
}

impl Monitor for HWFuzzMonitor
{
    /// the client monitor, mutable
    fn client_stats_mut(&mut self) -> &mut Vec<ClientStats> {
        &mut self.client_stats
    }

    /// the client monitor
    fn client_stats(&self) -> &[ClientStats] {
        &self.client_stats
    }

    /// Time this fuzzing run stated
    fn start_time(&mut self) -> Duration {
        self.start_time
    }

    fn display(&mut self, _event_msg: String, sender_id: ClientId) {
        let execs = self.total_execs();
        let execs_per_sec = self.execs_per_sec_pretty();
        {
            let client = self.client_stats_mut_for(sender_id).clone();

            let mut ui = self.ui.lock().unwrap();
            let data = ui.data();

            for (key, val) in &client.user_monitor {
                if key == "shared_mem" {
                    let str = val.to_string();
                    let bit_str = str.split("/").nth(0).unwrap();
                    let bits = i64::from_str_radix(bit_str, 10).unwrap();
                    data.add_max_coverage(bits as f64);
                }
            }
            
            let msg =  format!(
                "time: {}, corpus size: {}, taint violations: {}, execs: {}, exec/sec: {}",
                format_duration_hms(&(current_time() - self.start_time)),
                self.corpus_size(),
                self.objective_size(),
                execs,
                execs_per_sec,
            );
            data.add_message(msg.to_string());
        }
        let mut ui = self.ui.lock().unwrap();
        ui.try_tick();

        #[cfg(none)]
        if false {
            print!(
                "time: {}, clients: {}, interesting programs: {}, found taint violations: {}, execs: {}, exec/sec: {}",
                format_duration_hms(&(current_time() - self.start_time)),
                self.client_stats().len(),
                self.corpus_size(),
                self.objective_size(),
                self.total_execs(),
                self.execs_per_sec_pretty(),
            );
            let client = self.client_stats_mut_for(sender_id);
            for (key, val) in &client.user_monitor {
                print!(", {key}: {val}");
            }
            println!("");
        }
    }
}

impl HWFuzzMonitor
{
    /// Creates the monitor, using the `current_time` as `start_time`.
    pub fn new(ui : Arc<Mutex<FuzzUI>>) -> Self {
        Self {
            start_time: current_time(),
            client_stats: vec![],
            ui
        }
    }
}