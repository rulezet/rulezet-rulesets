rule TTP_XOR_MULT_DOSStub_beb6 {
  strings:
    $key_beb6 = { ea de [2] 9e c6 [2] d9 c4 [2] 9e d5 [2] d0 d9 [2] dc d3 [2] cb d8 [2] d0 96 [2] ed }

  condition:
    any of them
}