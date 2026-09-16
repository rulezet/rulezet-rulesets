rule TTP_XOR_MULT_DOSStub_5942 {
  strings:
    $key_5942 = { 0d 2a [2] 79 32 [2] 3e 30 [2] 79 21 [2] 37 2d [2] 3b 27 [2] 2c 2c [2] 37 62 [2] 0a }

  condition:
    any of them
}