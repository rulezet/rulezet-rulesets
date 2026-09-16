rule TTP_XOR_MULT_DOSStub_eb32 {
  strings:
    $key_eb32 = { bf 5a [2] cb 42 [2] 8c 40 [2] cb 51 [2] 85 5d [2] 89 57 [2] 9e 5c [2] 85 12 [2] b8 }

  condition:
    any of them
}