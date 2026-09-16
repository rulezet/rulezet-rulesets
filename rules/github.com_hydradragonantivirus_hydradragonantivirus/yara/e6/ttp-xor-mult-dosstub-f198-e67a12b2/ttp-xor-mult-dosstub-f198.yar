rule TTP_XOR_MULT_DOSStub_f198 {
  strings:
    $key_f198 = { a5 f0 [2] d1 e8 [2] 96 ea [2] d1 fb [2] 9f f7 [2] 93 fd [2] 84 f6 [2] 9f b8 [2] a2 }

  condition:
    any of them
}