rule TTP_XOR_MULT_DOSStub_4142 {
  strings:
    $key_4142 = { 15 2a [2] 61 32 [2] 26 30 [2] 61 21 [2] 2f 2d [2] 23 27 [2] 34 2c [2] 2f 62 [2] 12 }

  condition:
    any of them
}