rule TTP_XOR_MULT_DOSStub_234b {
  strings:
    $key_234b = { 77 23 [2] 03 3b [2] 44 39 [2] 03 28 [2] 4d 24 [2] 41 2e [2] 56 25 [2] 4d 6b [2] 70 }

  condition:
    any of them
}