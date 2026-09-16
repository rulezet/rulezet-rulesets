rule TTP_XOR_MULT_DOSStub_1548 {
  strings:
    $key_1548 = { 41 20 [2] 35 38 [2] 72 3a [2] 35 2b [2] 7b 27 [2] 77 2d [2] 60 26 [2] 7b 68 [2] 46 }

  condition:
    any of them
}