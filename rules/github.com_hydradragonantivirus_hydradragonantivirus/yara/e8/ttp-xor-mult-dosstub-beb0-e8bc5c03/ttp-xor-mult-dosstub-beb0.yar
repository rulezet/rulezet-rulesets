rule TTP_XOR_MULT_DOSStub_beb0 {
  strings:
    $key_beb0 = { ea d8 [2] 9e c0 [2] d9 c2 [2] 9e d3 [2] d0 df [2] dc d5 [2] cb de [2] d0 90 [2] ed }

  condition:
    any of them
}