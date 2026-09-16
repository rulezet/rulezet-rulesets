rule TTP_XOR_MULT_DOSStub_8596 {
  strings:
    $key_8596 = { d1 fe [2] a5 e6 [2] e2 e4 [2] a5 f5 [2] eb f9 [2] e7 f3 [2] f0 f8 [2] eb b6 [2] d6 }

  condition:
    any of them
}