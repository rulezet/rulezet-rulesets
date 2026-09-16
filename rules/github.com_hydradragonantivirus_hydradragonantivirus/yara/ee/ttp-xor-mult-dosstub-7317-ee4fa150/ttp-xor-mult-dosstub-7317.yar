rule TTP_XOR_MULT_DOSStub_7317 {
  strings:
    $key_7317 = { 27 7f [2] 53 67 [2] 14 65 [2] 53 74 [2] 1d 78 [2] 11 72 [2] 06 79 [2] 1d 37 [2] 20 }

  condition:
    any of them
}