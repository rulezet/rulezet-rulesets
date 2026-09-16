rule TTP_XOR_MULT_DOSStub_ace2 {
  strings:
    $key_ace2 = { f8 8a [2] 8c 92 [2] cb 90 [2] 8c 81 [2] c2 8d [2] ce 87 [2] d9 8c [2] c2 c2 [2] ff }

  condition:
    any of them
}