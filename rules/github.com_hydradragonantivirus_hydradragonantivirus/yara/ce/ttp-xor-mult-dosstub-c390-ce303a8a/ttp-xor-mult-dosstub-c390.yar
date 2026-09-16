rule TTP_XOR_MULT_DOSStub_c390 {
  strings:
    $key_c390 = { 97 f8 [2] e3 e0 [2] a4 e2 [2] e3 f3 [2] ad ff [2] a1 f5 [2] b6 fe [2] ad b0 [2] 90 }

  condition:
    any of them
}