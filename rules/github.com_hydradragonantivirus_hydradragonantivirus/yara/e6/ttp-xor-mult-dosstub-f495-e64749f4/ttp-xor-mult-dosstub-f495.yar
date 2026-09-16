rule TTP_XOR_MULT_DOSStub_f495 {
  strings:
    $key_f495 = { a0 fd [2] d4 e5 [2] 93 e7 [2] d4 f6 [2] 9a fa [2] 96 f0 [2] 81 fb [2] 9a b5 [2] a7 }

  condition:
    any of them
}