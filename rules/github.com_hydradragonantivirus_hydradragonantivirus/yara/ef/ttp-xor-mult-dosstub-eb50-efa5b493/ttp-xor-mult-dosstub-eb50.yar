rule TTP_XOR_MULT_DOSStub_eb50 {
  strings:
    $key_eb50 = { bf 38 [2] cb 20 [2] 8c 22 [2] cb 33 [2] 85 3f [2] 89 35 [2] 9e 3e [2] 85 70 [2] b8 }

  condition:
    any of them
}