rule TTP_XOR_MULT_DOSStub_5452 {
  strings:
    $key_5452 = { 00 3a [2] 74 22 [2] 33 20 [2] 74 31 [2] 3a 3d [2] 36 37 [2] 21 3c [2] 3a 72 [2] 07 }

  condition:
    any of them
}