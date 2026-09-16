rule TTP_XOR_MULT_DOSStub_eb0e {
  strings:
    $key_eb0e = { bf 66 [2] cb 7e [2] 8c 7c [2] cb 6d [2] 85 61 [2] 89 6b [2] 9e 60 [2] 85 2e [2] b8 }

  condition:
    any of them
}