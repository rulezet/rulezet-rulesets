rule TTP_XOR_MULT_DOSStub_e798 {
  strings:
    $key_e798 = { b3 f0 [2] c7 e8 [2] 80 ea [2] c7 fb [2] 89 f7 [2] 85 fd [2] 92 f6 [2] 89 b8 [2] b4 }

  condition:
    any of them
}