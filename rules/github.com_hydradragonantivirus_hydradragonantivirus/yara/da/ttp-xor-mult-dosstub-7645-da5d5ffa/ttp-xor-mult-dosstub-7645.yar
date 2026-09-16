rule TTP_XOR_MULT_DOSStub_7645 {
  strings:
    $key_7645 = { 22 2d [2] 56 35 [2] 11 37 [2] 56 26 [2] 18 2a [2] 14 20 [2] 03 2b [2] 18 65 [2] 25 }

  condition:
    any of them
}