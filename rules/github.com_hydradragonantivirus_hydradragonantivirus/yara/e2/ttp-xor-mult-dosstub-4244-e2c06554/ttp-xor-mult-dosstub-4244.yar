rule TTP_XOR_MULT_DOSStub_4244 {
  strings:
    $key_4244 = { 16 2c [2] 62 34 [2] 25 36 [2] 62 27 [2] 2c 2b [2] 20 21 [2] 37 2a [2] 2c 64 [2] 11 }

  condition:
    any of them
}