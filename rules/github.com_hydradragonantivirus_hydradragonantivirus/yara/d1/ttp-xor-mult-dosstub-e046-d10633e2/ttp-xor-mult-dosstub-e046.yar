rule TTP_XOR_MULT_DOSStub_e046 {
  strings:
    $key_e046 = { b4 2e [2] c0 36 [2] 87 34 [2] c0 25 [2] 8e 29 [2] 82 23 [2] 95 28 [2] 8e 66 [2] b3 }

  condition:
    any of them
}