rule TTP_XOR_MULT_DOSStub_eb49 {
  strings:
    $key_eb49 = { bf 21 [2] cb 39 [2] 8c 3b [2] cb 2a [2] 85 26 [2] 89 2c [2] 9e 27 [2] 85 69 [2] b8 }

  condition:
    any of them
}