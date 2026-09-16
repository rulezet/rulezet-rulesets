rule TTP_XOR_MULT_DOSStub_eb78 {
  strings:
    $key_eb78 = { bf 10 [2] cb 08 [2] 8c 0a [2] cb 1b [2] 85 17 [2] 89 1d [2] 9e 16 [2] 85 58 [2] b8 }

  condition:
    any of them
}