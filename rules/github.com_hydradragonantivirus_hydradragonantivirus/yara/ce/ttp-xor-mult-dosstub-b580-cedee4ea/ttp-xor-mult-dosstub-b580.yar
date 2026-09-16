rule TTP_XOR_MULT_DOSStub_b580 {
  strings:
    $key_b580 = { e1 e8 [2] 95 f0 [2] d2 f2 [2] 95 e3 [2] db ef [2] d7 e5 [2] c0 ee [2] db a0 [2] e6 }

  condition:
    any of them
}