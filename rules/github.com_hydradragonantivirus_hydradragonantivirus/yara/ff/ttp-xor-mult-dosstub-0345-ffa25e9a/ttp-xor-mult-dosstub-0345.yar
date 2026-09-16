rule TTP_XOR_MULT_DOSStub_0345 {
  strings:
    $key_0345 = { 57 2d [2] 23 35 [2] 64 37 [2] 23 26 [2] 6d 2a [2] 61 20 [2] 76 2b [2] 6d 65 [2] 50 }

  condition:
    any of them
}