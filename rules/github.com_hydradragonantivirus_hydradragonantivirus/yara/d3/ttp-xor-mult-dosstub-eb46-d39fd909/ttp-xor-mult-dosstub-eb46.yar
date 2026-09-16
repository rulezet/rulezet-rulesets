rule TTP_XOR_MULT_DOSStub_eb46 {
  strings:
    $key_eb46 = { bf 2e [2] cb 36 [2] 8c 34 [2] cb 25 [2] 85 29 [2] 89 23 [2] 9e 28 [2] 85 66 [2] b8 }

  condition:
    any of them
}