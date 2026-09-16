rule TTP_XOR_MULT_DOSStub_1342 {
  strings:
    $key_1342 = { 47 2a [2] 33 32 [2] 74 30 [2] 33 21 [2] 7d 2d [2] 71 27 [2] 66 2c [2] 7d 62 [2] 40 }

  condition:
    any of them
}