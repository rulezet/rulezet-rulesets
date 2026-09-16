rule TTP_XOR_MULT_DOSStub_5645 {
  strings:
    $key_5645 = { 02 2d [2] 76 35 [2] 31 37 [2] 76 26 [2] 38 2a [2] 34 20 [2] 23 2b [2] 38 65 [2] 05 }

  condition:
    any of them
}