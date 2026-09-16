rule TTP_XOR_MULT_DOSStub_acfd {
  strings:
    $key_acfd = { f8 95 [2] 8c 8d [2] cb 8f [2] 8c 9e [2] c2 92 [2] ce 98 [2] d9 93 [2] c2 dd [2] ff }

  condition:
    any of them
}