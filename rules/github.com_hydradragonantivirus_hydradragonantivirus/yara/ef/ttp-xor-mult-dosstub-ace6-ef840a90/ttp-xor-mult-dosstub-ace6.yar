rule TTP_XOR_MULT_DOSStub_ace6 {
  strings:
    $key_ace6 = { f8 8e [2] 8c 96 [2] cb 94 [2] 8c 85 [2] c2 89 [2] ce 83 [2] d9 88 [2] c2 c6 [2] ff }

  condition:
    any of them
}