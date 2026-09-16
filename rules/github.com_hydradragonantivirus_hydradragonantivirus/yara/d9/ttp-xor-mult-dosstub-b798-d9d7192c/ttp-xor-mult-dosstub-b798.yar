rule TTP_XOR_MULT_DOSStub_b798 {
  strings:
    $key_b798 = { e3 f0 [2] 97 e8 [2] d0 ea [2] 97 fb [2] d9 f7 [2] d5 fd [2] c2 f6 [2] d9 b8 [2] e4 }

  condition:
    any of them
}