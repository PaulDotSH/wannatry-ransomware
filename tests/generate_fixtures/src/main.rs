// Generates a realistic directory tree mimicking a user's home folder for
// benchmarking and integration testing. Run via `cargo gen-fixtures`.
//
// Usage:
//   cargo run --package generate-fixtures -- <root> [scale]
//
// `<root>`  output directory (default: tests/fixtures)
// `<scale>` size/count multiplier in [0,1] to shrink the tree for quick runs
//           (default: 1.0 = full ~450 files / ~10-15 GB)

use rand::Rng;
use rand::RngCore;
use std::fs;
use std::io::Write;
use std::path::Path;

struct FileSpec {
    count: usize,
    min_size: u64,
    max_size: u64,
    extensions: &'static [&'static str],
}

const SPECS: &[(&str, &[FileSpec])] = &[
    ("Documents/small", &[FileSpec {
        count: 200,
        min_size: 1024,
        max_size: 512_000,
        extensions: &["txt", "md", "csv", "json"],
    }]),
    ("Documents/medium", &[FileSpec {
        count: 50,
        min_size: 1_048_576,
        max_size: 20_971_520,
        extensions: &["pdf", "docx", "png", "jpg"],
    }]),
    ("Documents/large", &[FileSpec {
        count: 5,
        min_size: 52_428_800,
        max_size: 524_288_000,
        extensions: &["mp4", "zip", "iso"],
    }]),
    ("Pictures/small", &[FileSpec {
        count: 100,
        min_size: 10_240,
        max_size: 512_000,
        extensions: &["png", "jpg", "gif"],
    }]),
    ("Pictures/large", &[FileSpec {
        count: 10,
        min_size: 5_242_880,
        max_size: 52_428_800,
        extensions: &["png", "jpg"],
    }]),
    ("Downloads/small", &[FileSpec {
        count: 50,
        min_size: 1024,
        max_size: 102_400,
        extensions: &["pdf", "zip"],
    }]),
    ("Downloads/large", &[FileSpec {
        count: 3,
        min_size: 104_857_600,
        max_size: 1_073_741_824,
        extensions: &["iso"],
    }]),
    ("Desktop/misc", &[FileSpec {
        count: 30,
        min_size: 1024,
        max_size: 2_097_152,
        extensions: &["txt", "lnk"],
    }]),
    (".hidden", &[FileSpec {
        count: 10,
        min_size: 1024,
        max_size: 10_240,
        extensions: &["config", "env"],
    }]),
];

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let root = args.get(1).cloned().unwrap_or_else(|| "tests/fixtures".into());
    let scale: f64 = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(1.0);

    let (file_count, total_bytes) = generate_fixtures(Path::new(&root), scale);
    println!(
        "Generated {} files ({:.2} GB) under {}",
        file_count,
        total_bytes as f64 / (1024.0 * 1024.0 * 1024.0),
        root
    );
}

fn generate_fixtures(root: &Path, scale: f64) -> (usize, u64) {
    let mut rng = rand::thread_rng();
    let mut total_files = 0usize;
    let mut total_bytes = 0u64;

    for (dir, specs) in SPECS {
        for spec in *specs {
            let count = (spec.count as f64 * scale).round().max(1.0) as usize;
            for i in 0..count {
                let ext = spec.extensions[i % spec.extensions.len()];
                let size = rand_size(spec, scale, &mut rng);
                let path = root.join(dir).join(format!("file_{:04}.{}", i, ext));
                fs::create_dir_all(path.parent().unwrap()).unwrap();
                write_file(&path, size, &mut rng);
                total_files += 1;
                total_bytes += size;
            }
        }
    }

    (total_files, total_bytes)
}

fn rand_size(spec: &FileSpec, scale: f64, rng: &mut impl Rng) -> u64 {
    let min = (spec.min_size as f64 * scale) as u64;
    let max = ((spec.max_size as f64 * scale) as u64).max(min + 1);
    rng.gen_range(min..=max)
}

fn write_file(path: &Path, size: u64, rng: &mut impl RngCore) {
    let mut f = fs::File::create(path).unwrap();
    let mut buf = vec![0u8; 1_048_576];
    let mut remaining = size;
    while remaining > 0 {
        let chunk = remaining.min(buf.len() as u64) as usize;
        rng.fill_bytes(&mut buf[..chunk]);
        f.write_all(&buf[..chunk]).unwrap();
        remaining -= chunk as u64;
    }
}
