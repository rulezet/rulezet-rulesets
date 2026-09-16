rule TTP_XOR_MULT_DOSStub_d542 {
  strings:
    $key_d542 = { 81 2a [2] f5 32 [2] b2 30 [2] f5 21 [2] bb 2d [2] b7 27 [2] a0 2c [2] bb 62 [2] 86 }

  condition:
    any of them
}