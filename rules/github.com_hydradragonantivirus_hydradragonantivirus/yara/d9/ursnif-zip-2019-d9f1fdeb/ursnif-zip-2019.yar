rule ursnif_zip_2019 {
  meta:
    author    = "jeFF0Falltrades"
    reference = "https://www.fortinet.com/blog/threat-research/ursnif-variant-spreading-word-document.html"

  strings:
    $doc_name   = { 69 6e 66 6f 5f ?? ?? 2e ?? ?? 2e 64 6f 63 }      $zip_header = { 50 4B 03 04 }
    $zip_footer = { 50 4B 05 06 00 }

  condition:
    ($zip_header at 0) and ($doc_name in (0..48)) and ($zip_footer in (filesize - 150..filesize))
}