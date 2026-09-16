rule TTP_XOR_MULT_DOSStub_ace4 {
  strings:
    $key_ace4 = { f8 8c [2] 8c 94 [2] cb 96 [2] 8c 87 [2] c2 8b [2] ce 81 [2] d9 8a [2] c2 c4 [2] ff }

  condition:
    any of them
}