rule TTP_XOR_MULT_DOSStub_e5b1 {
  strings:
    $key_e5b1 = { b1 d9 [2] c5 c1 [2] 82 c3 [2] c5 d2 [2] 8b de [2] 87 d4 [2] 90 df [2] 8b 91 [2] b6 }

  condition:
    any of them
}