rule TTP_XOR_MULT_DOSStub_eb28 {
  strings:
    $key_eb28 = { bf 40 [2] cb 58 [2] 8c 5a [2] cb 4b [2] 85 47 [2] 89 4d [2] 9e 46 [2] 85 08 [2] b8 }

  condition:
    any of them
}