rule TTP_XOR_MULT_DOSStub_d544 {
  strings:
    $key_d544 = { 81 2c [2] f5 34 [2] b2 36 [2] f5 27 [2] bb 2b [2] b7 21 [2] a0 2a [2] bb 64 [2] 86 }

  condition:
    any of them
}