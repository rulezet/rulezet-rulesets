rule TTP_XOR_MULT_DOSStub_eb26 {
  strings:
    $key_eb26 = { bf 4e [2] cb 56 [2] 8c 54 [2] cb 45 [2] 85 49 [2] 89 43 [2] 9e 48 [2] 85 06 [2] b8 }

  condition:
    any of them
}