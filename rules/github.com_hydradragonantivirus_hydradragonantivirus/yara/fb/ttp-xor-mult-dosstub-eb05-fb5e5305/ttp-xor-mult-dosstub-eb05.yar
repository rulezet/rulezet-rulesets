rule TTP_XOR_MULT_DOSStub_eb05 {
  strings:
    $key_eb05 = { bf 6d [2] cb 75 [2] 8c 77 [2] cb 66 [2] 85 6a [2] 89 60 [2] 9e 6b [2] 85 25 [2] b8 }

  condition:
    any of them
}