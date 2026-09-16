rule TTP_XOR_MULT_DOSStub_acde {
  strings:
    $key_acde = { f8 b6 [2] 8c ae [2] cb ac [2] 8c bd [2] c2 b1 [2] ce bb [2] d9 b0 [2] c2 fe [2] ff }

  condition:
    any of them
}