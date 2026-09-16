rule TTP_XOR_MULT_DOSStub_b5c3 {
  strings:
    $key_b5c3 = { e1 ab [2] 95 b3 [2] d2 b1 [2] 95 a0 [2] db ac [2] d7 a6 [2] c0 ad [2] db e3 [2] e6 }

  condition:
    any of them
}