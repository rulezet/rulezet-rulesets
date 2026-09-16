rule TTP_XOR_MULT_DOSStub_e384 {
  strings:
    $key_e384 = { b7 ec [2] c3 f4 [2] 84 f6 [2] c3 e7 [2] 8d eb [2] 81 e1 [2] 96 ea [2] 8d a4 [2] b0 }

  condition:
    any of them
}