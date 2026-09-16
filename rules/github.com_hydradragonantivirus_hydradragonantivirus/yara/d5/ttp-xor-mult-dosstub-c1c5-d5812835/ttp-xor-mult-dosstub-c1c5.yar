rule TTP_XOR_MULT_DOSStub_c1c5 {
  strings:
    $key_c1c5 = { 95 ad [2] e1 b5 [2] a6 b7 [2] e1 a6 [2] af aa [2] a3 a0 [2] b4 ab [2] af e5 [2] 92 }

  condition:
    any of them
}