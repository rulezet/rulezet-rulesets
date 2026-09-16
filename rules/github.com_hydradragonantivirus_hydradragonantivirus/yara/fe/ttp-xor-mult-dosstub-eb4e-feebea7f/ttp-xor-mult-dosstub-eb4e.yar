rule TTP_XOR_MULT_DOSStub_eb4e {
  strings:
    $key_eb4e = { bf 26 [2] cb 3e [2] 8c 3c [2] cb 2d [2] 85 21 [2] 89 2b [2] 9e 20 [2] 85 6e [2] b8 }

  condition:
    any of them
}