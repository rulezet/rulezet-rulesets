rule TTP_XOR_MULT_DOSStub_e649 {
  strings:
    $key_e649 = { b2 21 [2] c6 39 [2] 81 3b [2] c6 2a [2] 88 26 [2] 84 2c [2] 93 27 [2] 88 69 [2] b5 }

  condition:
    any of them
}