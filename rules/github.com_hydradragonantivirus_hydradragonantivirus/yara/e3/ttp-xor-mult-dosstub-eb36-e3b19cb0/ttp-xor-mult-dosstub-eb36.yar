rule TTP_XOR_MULT_DOSStub_eb36 {
  strings:
    $key_eb36 = { bf 5e [2] cb 46 [2] 8c 44 [2] cb 55 [2] 85 59 [2] 89 53 [2] 9e 58 [2] 85 16 [2] b8 }

  condition:
    any of them
}