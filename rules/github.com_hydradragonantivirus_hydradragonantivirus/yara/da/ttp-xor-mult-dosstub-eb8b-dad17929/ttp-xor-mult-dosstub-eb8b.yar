rule TTP_XOR_MULT_DOSStub_eb8b {
  strings:
    $key_eb8b = { bf e3 [2] cb fb [2] 8c f9 [2] cb e8 [2] 85 e4 [2] 89 ee [2] 9e e5 [2] 85 ab [2] b8 }

  condition:
    any of them
}