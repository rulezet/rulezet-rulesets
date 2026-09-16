rule TTP_XOR_MULT_DOSStub_ebf9 {
  strings:
    $key_ebf9 = { bf 91 [2] cb 89 [2] 8c 8b [2] cb 9a [2] 85 96 [2] 89 9c [2] 9e 97 [2] 85 d9 [2] b8 }

  condition:
    any of them
}