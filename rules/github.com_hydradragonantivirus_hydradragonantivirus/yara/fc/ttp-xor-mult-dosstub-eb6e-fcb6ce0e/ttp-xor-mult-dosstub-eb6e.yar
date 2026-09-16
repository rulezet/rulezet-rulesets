rule TTP_XOR_MULT_DOSStub_eb6e {
  strings:
    $key_eb6e = { bf 06 [2] cb 1e [2] 8c 1c [2] cb 0d [2] 85 01 [2] 89 0b [2] 9e 00 [2] 85 4e [2] b8 }

  condition:
    any of them
}