rule TTP_XOR_MULT_DOSStub_c182 {
  strings:
    $key_c182 = { 95 ea [2] e1 f2 [2] a6 f0 [2] e1 e1 [2] af ed [2] a3 e7 [2] b4 ec [2] af a2 [2] 92 }

  condition:
    any of them
}