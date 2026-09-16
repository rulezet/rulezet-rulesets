rule TTP_XOR_MULT_DOSStub_eb54 {
  strings:
    $key_eb54 = { bf 3c [2] cb 24 [2] 8c 26 [2] cb 37 [2] 85 3b [2] 89 31 [2] 9e 3a [2] 85 74 [2] b8 }

  condition:
    any of them
}