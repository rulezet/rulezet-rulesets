rule TTP_XOR_MULT_DOSStub_b393 {
  strings:
    $key_b393 = { e7 fb [2] 93 e3 [2] d4 e1 [2] 93 f0 [2] dd fc [2] d1 f6 [2] c6 fd [2] dd b3 [2] e0 }

  condition:
    any of them
}