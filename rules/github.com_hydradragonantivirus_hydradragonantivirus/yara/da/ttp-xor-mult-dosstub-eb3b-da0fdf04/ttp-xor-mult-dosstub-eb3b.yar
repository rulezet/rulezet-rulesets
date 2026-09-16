rule TTP_XOR_MULT_DOSStub_eb3b {
  strings:
    $key_eb3b = { bf 53 [2] cb 4b [2] 8c 49 [2] cb 58 [2] 85 54 [2] 89 5e [2] 9e 55 [2] 85 1b [2] b8 }

  condition:
    any of them
}