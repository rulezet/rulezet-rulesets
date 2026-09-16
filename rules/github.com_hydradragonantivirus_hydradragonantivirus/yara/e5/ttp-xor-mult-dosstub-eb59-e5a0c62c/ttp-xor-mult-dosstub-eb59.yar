rule TTP_XOR_MULT_DOSStub_eb59 {
  strings:
    $key_eb59 = { bf 31 [2] cb 29 [2] 8c 2b [2] cb 3a [2] 85 36 [2] 89 3c [2] 9e 37 [2] 85 79 [2] b8 }

  condition:
    any of them
}