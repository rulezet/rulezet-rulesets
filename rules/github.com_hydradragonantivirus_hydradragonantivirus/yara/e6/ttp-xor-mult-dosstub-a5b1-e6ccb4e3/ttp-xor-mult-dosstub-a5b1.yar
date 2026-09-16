rule TTP_XOR_MULT_DOSStub_a5b1 {
  strings:
    $key_a5b1 = { f1 d9 [2] 85 c1 [2] c2 c3 [2] 85 d2 [2] cb de [2] c7 d4 [2] d0 df [2] cb 91 [2] f6 }

  condition:
    any of them
}