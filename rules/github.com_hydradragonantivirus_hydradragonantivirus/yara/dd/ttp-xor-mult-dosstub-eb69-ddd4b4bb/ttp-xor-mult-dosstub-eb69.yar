rule TTP_XOR_MULT_DOSStub_eb69 {
  strings:
    $key_eb69 = { bf 01 [2] cb 19 [2] 8c 1b [2] cb 0a [2] 85 06 [2] 89 0c [2] 9e 07 [2] 85 49 [2] b8 }

  condition:
    any of them
}