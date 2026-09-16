rule TTP_XOR_MULT_DOSStub_45c5 {
  strings:
    $key_45c5 = { 11 ad [2] 65 b5 [2] 22 b7 [2] 65 a6 [2] 2b aa [2] 27 a0 [2] 30 ab [2] 2b e5 [2] 16 }

  condition:
    any of them
}