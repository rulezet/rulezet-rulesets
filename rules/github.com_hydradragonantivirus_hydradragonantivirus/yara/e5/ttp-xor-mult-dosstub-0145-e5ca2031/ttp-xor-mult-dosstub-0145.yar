rule TTP_XOR_MULT_DOSStub_0145 {
  strings:
    $key_0145 = { 55 2d [2] 21 35 [2] 66 37 [2] 21 26 [2] 6f 2a [2] 63 20 [2] 74 2b [2] 6f 65 [2] 52 }

  condition:
    any of them
}