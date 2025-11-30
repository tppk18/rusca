use axum::{response::IntoResponse, Json};
use serde::Serialize;
use std::{fs, path::Path};

#[derive(Serialize)]
struct ReportInfo {
    file: String,   // "scan_12-34-56.html"
    url: String,    // "/results/2025-11-30/scan_12-34-56.html"
}

pub async fn list_reports() -> impl IntoResponse {
    let mut out = Vec::new();
    let base = Path::new("results");

    if let Ok(files) = fs::read_dir(base) {
        for f in files.flatten() {
            let fname = f.file_name().to_string_lossy().to_string();
            if !fname.ends_with(".html") {
                continue;
            }
            let url = format!("/results/{}", fname);
            out.push(ReportInfo {
                file: fname,
                url,
            });
        }
    }

    // Можно отсортировать по дате/имени в обратном порядке
    out.sort_by(|a, b| b.file.cmp(&a.file));

    Json(out)
}
