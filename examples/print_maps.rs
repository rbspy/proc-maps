extern crate proc_maps;

fn main() {
    let args: Vec<String> = std::env::args().collect();

    let pid = if args.len() > 1 {
        args[1].parse().expect("invalid pid")
    } else {
        panic!("Usage: print_maps <PID>");
    };

    println!(
        "{:^30} {:^16} {:^7} {}",
        "ADDRESSES", "SIZE", "MODES", "PATH"
    );

    let empty_path = std::path::Path::new("");
    let maps = proc_maps::get_process_maps(pid).expect("failed to get proc maps");
    for map in maps {
        let r_flag = if map.is_read() { "R" } else { "-" };
        let w_flag = if map.is_write() { "W" } else { "-" };
        let x_flag = if map.is_exec() { "X" } else { "-" };
        let filename = map.filename().unwrap_or(empty_path).to_str().unwrap_or("-");
        println!(
            "{:>30} {:>16} [{} {} {}] {}",
            format!("{:#x}-{:#x}", map.start(), map.start() + map.size()),
            map.size(),
            r_flag,
            w_flag,
            x_flag,
            filename,
        );
    }
}
