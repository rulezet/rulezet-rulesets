rule TTP_XOR_MULT_DOSStub_4048 {
  strings:
    $key_4048 = { 14 20 [2] 60 38 [2] 27 3a [2] 60 2b [2] 2e 27 [2] 22 2d [2] 35 26 [2] 2e 68 [2] 13 }

  condition:
    any of them
}