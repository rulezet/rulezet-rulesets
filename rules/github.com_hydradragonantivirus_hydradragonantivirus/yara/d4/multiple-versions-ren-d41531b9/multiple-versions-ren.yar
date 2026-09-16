rule multiple_versions_ren: PDF {
  meta:
    author      = "Glenn Edwards (@hiddenillusion)"
    version     = "0.1"
    description = "Written very generically and doesn't hold any weight - just something that might be useful to know about to help show incremental updates to the file being analyzed"
    weight      = 0

  strings:
    $magic = "%PDF"
    $s0    = "trailer"
    $s1    = "%%EOF"

  condition:
    $magic at 0 and #s0 > 1 and #s1 > 1
}