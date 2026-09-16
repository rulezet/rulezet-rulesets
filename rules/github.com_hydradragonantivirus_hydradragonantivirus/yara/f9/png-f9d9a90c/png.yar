rule png: PNG {
  meta:
    author = "Joan Bono"

  strings:
    $a = { 89 50 4E 47 0D 0A 1A 0A }
    $b = "IHDR"
    $c = "IDAT"
    $d = "IEND"

  condition:
    $a at 0 and for any of ($b, $c): (@ > @a) and $d
}