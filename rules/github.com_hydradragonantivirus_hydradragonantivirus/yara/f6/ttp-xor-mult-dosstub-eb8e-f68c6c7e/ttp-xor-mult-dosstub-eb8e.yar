rule TTP_XOR_MULT_DOSStub_eb8e {
  strings:
    $key_eb8e = { bf e6 [2] cb fe [2] 8c fc [2] cb ed [2] 85 e1 [2] 89 eb [2] 9e e0 [2] 85 ae [2] b8 }

  condition:
    any of them
}