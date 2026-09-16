rule TTP_XOR_MULT_DOSStub_75c5 {
  strings:
    $key_75c5 = { 21 ad [2] 55 b5 [2] 12 b7 [2] 55 a6 [2] 1b aa [2] 17 a0 [2] 00 ab [2] 1b e5 [2] 26 }

  condition:
    any of them
}