rule jpg_with_SPIFF: JPG {
  meta:
    author = "Jaume Martin"

  strings:
    $a = { FF D8 FF E8 ?? ?? 53 50 49 46 46 00 }

  condition:
    $a at 0
}