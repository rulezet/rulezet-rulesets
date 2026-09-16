rule TTP_XOR_MULT_DOSStub_4377 {
  strings:
    $key_4377 = { 17 1f [2] 63 07 [2] 24 05 [2] 63 14 [2] 2d 18 [2] 21 12 [2] 36 19 [2] 2d 57 [2] 10 }

  condition:
    any of them
}