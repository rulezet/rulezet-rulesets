rule TTP_XOR_MULT_DOSStub_3c42 {
  strings:
    $key_3c42 = { 68 2a [2] 1c 32 [2] 5b 30 [2] 1c 21 [2] 52 2d [2] 5e 27 [2] 49 2c [2] 52 62 [2] 6f }

  condition:
    any of them
}