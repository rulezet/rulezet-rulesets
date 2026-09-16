rule TTP_XOR_MULT_DOSStub_eb03 {
  strings:
    $key_eb03 = { bf 6b [2] cb 73 [2] 8c 71 [2] cb 60 [2] 85 6c [2] 89 66 [2] 9e 6d [2] 85 23 [2] b8 }

  condition:
    any of them
}