rule TTP_XOR_MULT_DOSStub_e642 {
  strings:
    $key_e642 = { b2 2a [2] c6 32 [2] 81 30 [2] c6 21 [2] 88 2d [2] 84 27 [2] 93 2c [2] 88 62 [2] b5 }

  condition:
    any of them
}