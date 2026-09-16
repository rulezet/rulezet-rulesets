rule TTP_XOR_MULT_DOSStub_4c42 {
  strings:
    $key_4c42 = { 18 2a [2] 6c 32 [2] 2b 30 [2] 6c 21 [2] 22 2d [2] 2e 27 [2] 39 2c [2] 22 62 [2] 1f }

  condition:
    any of them
}