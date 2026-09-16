rule avi: AVI {
  meta:
    author = "Joan Bono"

  strings:
    $a = "RIFF"

  condition:
    $a at 0
}