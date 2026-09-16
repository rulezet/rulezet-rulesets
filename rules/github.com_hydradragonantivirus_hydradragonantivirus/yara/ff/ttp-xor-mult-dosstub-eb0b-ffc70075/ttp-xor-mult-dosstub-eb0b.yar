rule TTP_XOR_MULT_DOSStub_eb0b {
  strings:
    $key_eb0b = { bf 63 [2] cb 7b [2] 8c 79 [2] cb 68 [2] 85 64 [2] 89 6e [2] 9e 65 [2] 85 2b [2] b8 }

  condition:
    any of them
}