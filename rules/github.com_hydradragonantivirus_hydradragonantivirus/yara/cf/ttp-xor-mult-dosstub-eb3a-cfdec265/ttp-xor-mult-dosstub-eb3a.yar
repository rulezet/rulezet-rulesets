rule TTP_XOR_MULT_DOSStub_eb3a {
  strings:
    $key_eb3a = { bf 52 [2] cb 4a [2] 8c 48 [2] cb 59 [2] 85 55 [2] 89 5f [2] 9e 54 [2] 85 1a [2] b8 }

  condition:
    any of them
}