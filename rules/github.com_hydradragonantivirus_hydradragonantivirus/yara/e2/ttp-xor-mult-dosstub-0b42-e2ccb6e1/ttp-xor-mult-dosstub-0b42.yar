rule TTP_XOR_MULT_DOSStub_0b42 {
  strings:
    $key_0b42 = { 5f 2a [2] 2b 32 [2] 6c 30 [2] 2b 21 [2] 65 2d [2] 69 27 [2] 7e 2c [2] 65 62 [2] 58 }

  condition:
    any of them
}