rule TTP_XOR_MULT_DOSStub_0442 {
  strings:
    $key_0442 = { 50 2a [2] 24 32 [2] 63 30 [2] 24 21 [2] 6a 2d [2] 66 27 [2] 71 2c [2] 6a 62 [2] 57 }

  condition:
    any of them
}