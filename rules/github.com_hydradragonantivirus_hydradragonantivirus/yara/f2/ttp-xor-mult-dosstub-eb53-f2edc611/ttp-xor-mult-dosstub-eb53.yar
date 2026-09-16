rule TTP_XOR_MULT_DOSStub_eb53 {
  strings:
    $key_eb53 = { bf 3b [2] cb 23 [2] 8c 21 [2] cb 30 [2] 85 3c [2] 89 36 [2] 9e 3d [2] 85 73 [2] b8 }

  condition:
    any of them
}