rule TTP_XOR_MULT_DOSStub_ace9 {
  strings:
    $key_ace9 = { f8 81 [2] 8c 99 [2] cb 9b [2] 8c 8a [2] c2 86 [2] ce 8c [2] d9 87 [2] c2 c9 [2] ff }

  condition:
    any of them
}