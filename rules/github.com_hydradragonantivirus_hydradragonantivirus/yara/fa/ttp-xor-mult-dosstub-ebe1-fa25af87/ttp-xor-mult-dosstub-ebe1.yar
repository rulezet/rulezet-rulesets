rule TTP_XOR_MULT_DOSStub_ebe1 {
  strings:
    $key_ebe1 = { bf 89 [2] cb 91 [2] 8c 93 [2] cb 82 [2] 85 8e [2] 89 84 [2] 9e 8f [2] 85 c1 [2] b8 }

  condition:
    any of them
}