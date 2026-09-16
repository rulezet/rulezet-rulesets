rule TTP_XOR_MULT_DOSStub_eb16 {
  strings:
    $key_eb16 = { bf 7e [2] cb 66 [2] 8c 64 [2] cb 75 [2] 85 79 [2] 89 73 [2] 9e 78 [2] 85 36 [2] b8 }

  condition:
    any of them
}