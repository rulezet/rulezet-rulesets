rule TTP_XOR_MULT_DOSStub_ebe6 {
  strings:
    $key_ebe6 = { bf 8e [2] cb 96 [2] 8c 94 [2] cb 85 [2] 85 89 [2] 89 83 [2] 9e 88 [2] 85 c6 [2] b8 }

  condition:
    any of them
}