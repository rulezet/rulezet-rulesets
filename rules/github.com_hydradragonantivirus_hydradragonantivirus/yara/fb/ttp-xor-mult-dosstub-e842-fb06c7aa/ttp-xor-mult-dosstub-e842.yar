rule TTP_XOR_MULT_DOSStub_e842 {
  strings:
    $key_e842 = { bc 2a [2] c8 32 [2] 8f 30 [2] c8 21 [2] 86 2d [2] 8a 27 [2] 9d 2c [2] 86 62 [2] bb }

  condition:
    any of them
}