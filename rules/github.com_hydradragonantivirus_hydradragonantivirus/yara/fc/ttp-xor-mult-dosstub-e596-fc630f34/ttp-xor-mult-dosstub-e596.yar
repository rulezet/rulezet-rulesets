rule TTP_XOR_MULT_DOSStub_e596 {
  strings:
    $key_e596 = { b1 fe [2] c5 e6 [2] 82 e4 [2] c5 f5 [2] 8b f9 [2] 87 f3 [2] 90 f8 [2] 8b b6 [2] b6 }

  condition:
    any of them
}