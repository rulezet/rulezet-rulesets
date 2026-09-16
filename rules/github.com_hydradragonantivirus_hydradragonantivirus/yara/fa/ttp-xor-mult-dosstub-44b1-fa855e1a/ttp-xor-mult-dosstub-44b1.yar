rule TTP_XOR_MULT_DOSStub_44b1 {
  strings:
    $key_44b1 = { 10 d9 [2] 64 c1 [2] 23 c3 [2] 64 d2 [2] 2a de [2] 26 d4 [2] 31 df [2] 2a 91 [2] 17 }

  condition:
    any of them
}