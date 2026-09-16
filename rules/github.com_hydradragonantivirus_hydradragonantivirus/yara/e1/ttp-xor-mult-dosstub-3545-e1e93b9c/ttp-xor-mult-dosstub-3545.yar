rule TTP_XOR_MULT_DOSStub_3545 {
  strings:
    $key_3545 = { 61 2d [2] 15 35 [2] 52 37 [2] 15 26 [2] 5b 2a [2] 57 20 [2] 40 2b [2] 5b 65 [2] 66 }

  condition:
    any of them
}