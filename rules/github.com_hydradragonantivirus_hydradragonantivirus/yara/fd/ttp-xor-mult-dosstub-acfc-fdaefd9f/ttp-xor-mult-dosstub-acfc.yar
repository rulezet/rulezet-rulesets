rule TTP_XOR_MULT_DOSStub_acfc {
  strings:
    $key_acfc = { f8 94 [2] 8c 8c [2] cb 8e [2] 8c 9f [2] c2 93 [2] ce 99 [2] d9 92 [2] c2 dc [2] ff }

  condition:
    any of them
}