rule TTP_XOR_MULT_DOSStub_eb72 {
  strings:
    $key_eb72 = { bf 1a [2] cb 02 [2] 8c 00 [2] cb 11 [2] 85 1d [2] 89 17 [2] 9e 1c [2] 85 52 [2] b8 }

  condition:
    any of them
}