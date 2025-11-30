// export.rs
use std::{
    fs::{self, OpenOptions},
    io::Write,
    net::SocketAddr,
    path::PathBuf,
};

use chrono::Local;
use crate::model::Finding;

/// Экраним только самое опасное (< и >), чтобы не ломать HTML
fn escape_html(s: &str) -> String {
    s.replace('<', "&lt;").replace('>', "&gt;")
}

/// Рендер одной строки таблицы
fn render_row(
    addr: &SocketAddr,
    finding: Option<&Finding>,
    time_str: &str,
) -> String {
    let (kind_label, title, details) = if let Some(f) = finding {
        let kind = f.kind.label(); // предполагаю, что у FindingKind есть метод label()
        let t = f.title.as_deref().unwrap_or("");
        let d = f.details.as_deref().unwrap_or("");
        (kind, t, d)
    } else {
        ("", "", "")
    };

    let title_esc = escape_html(title);
    let details_esc = escape_html(details);
    let combined = if !title_esc.is_empty() && !details_esc.is_empty() {
        format!("{title} — {details}", title = title_esc, details = details_esc)
    } else if !title_esc.is_empty() {
        title_esc
    } else {
        details_esc
    };

    format!(
        "<tr><td>{time}</td><td><code>{addr}</code></td><td>{kind}</td><td>{combined}</td></tr>",
        time = time_str,
        addr = addr,
        kind = kind_label,
        combined = combined
    )
}

/// Дописывает строку в html-лог за текущую дату: results/YYYY-MM-DD.html
pub fn append_html_event(
    addr: &SocketAddr,
    finding: Option<&Finding>,
) -> std::io::Result<()> {
    let now = Local::now();
    let date_str = now.format("%Y-%m-%d").to_string();
    let time_str = now.format("%H:%M:%S").to_string();

    let base_dir = PathBuf::from("results");
    fs::create_dir_all(&base_dir)?;

    let path = base_dir.join(format!("{date_str}.html"));
    let is_new = !path.exists();

    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)?;

    if is_new {
        // Пишем шапку только один раз в день
        write!(
            file,
            r#"<!DOCTYPE html>
<html lang="ru">
<head>
<meta charset="UTF-8">
<title>Rusca Scan Log {date}</title>
<style>
body {{ font-family: system-ui, sans-serif; background:#020617; color:#e5e7eb; padding:16px; }}
h1 {{ color:#fbbf24; }}
table {{ border-collapse: collapse; width:100%; margin-top:12px; }}
th, td {{ border:1px solid #4b5563; padding:6px 8px; font-size:0.9rem; }}
th {{ background:#111827; }}
tr:nth-child(even) {{ background:#030712; }}
.badge {{ display:inline-block; padding:2px 6px; border-radius:4px; background:#1f2937; font-size:0.75rem; margin-right:4px; }}
code {{ color:#93c5fd; }}
</style>
</head>
<body>
<h1>Журнал сканирования за {date}</h1>
<table>
  <thead>
    <tr>
      <th>Время</th>
      <th>Адрес</th>
      <th>Тип</th>
      <th>Title / баннер</th>
    </tr>
  </thead>
  <tbody>
"#,
            date = date_str
        )?;
    }

    let row = render_row(addr, finding, &time_str);
    writeln!(file, "{}", row)?;

    // Никаких закрывающих тегов — чтобы можно было дописывать дальше
    Ok(())
}

/// Обновляет существующую строку для данного сокета (IP:PORT) в html-логе за сегодня.
/// Если строки ещё нет — добавляет новую.
///
/// Идея: когда сначала нашли сервис, а потом добрутили креды,
/// можно перезаписать строку, добавив логин/пароль в details/title.
pub fn update_html_event(
    addr: &SocketAddr,
    finding: Option<&Finding>,
) -> std::io::Result<()> {
    let now = Local::now();
    let date_str = now.format("%Y-%m-%d").to_string();
    let time_str = now.format("%H:%M:%S").to_string();

    let base_dir = PathBuf::from("results");
    fs::create_dir_all(&base_dir)?;

    let path = base_dir.join(format!("{date_str}.html"));

    // Если файла ещё нет — просто ведём себя как append
    if !path.exists() {
        return append_html_event(addr, finding);
    }

    let content = fs::read_to_string(&path)?;
    let mut lines: Vec<String> = content.lines().map(|l| l.to_string()).collect();

    let needle = format!("<code>{}</code>", addr);
    let new_row = render_row(addr, finding, &time_str);

    // Ищем последнюю строку с этим сокетом и заменяем её
    let mut replaced = false;
    for line in lines.iter_mut().rev() {
        if line.contains(&needle) && line.contains("<tr") && line.contains("</tr>") {
            *line = new_row.clone();
            replaced = true;
            break;
        }
    }

    // Если ничего не нашли — добавляем новую строку в конец
    if !replaced {
        lines.push(new_row);
    }

    let new_content = lines.join("\n");
    fs::write(&path, new_content)?;

    Ok(())
}
