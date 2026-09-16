rule haspng {
  meta:
    description = "Finds PE files with embedded PNG images, not useful for detecting badness"
    author = "Paul Melson @pmelson"
    date = "March 5, 2023"
  strings:
    $png = { 89 50 4e 47 }
    $ihdr = "IHDR"
    $idat = "IDAT"
    $iend = "IEND"
  condition:
    uint16(0) == 0x5a4d and all of them
}