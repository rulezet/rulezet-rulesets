rule TTP_XOR_MULT_DOSStub_ebb0 {
  strings:
    $key_ebb0 = { bf d8 [2] cb c0 [2] 8c c2 [2] cb d3 [2] 85 df [2] 89 d5 [2] 9e de [2] 85 90 [2] b8 }

  condition:
    any of them
}