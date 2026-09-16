rule TTP_XOR_MULT_DOSStub_e646 {
  strings:
    $key_e646 = { b2 2e [2] c6 36 [2] 81 34 [2] c6 25 [2] 88 29 [2] 84 23 [2] 93 28 [2] 88 66 [2] b5 }

  condition:
    any of them
}