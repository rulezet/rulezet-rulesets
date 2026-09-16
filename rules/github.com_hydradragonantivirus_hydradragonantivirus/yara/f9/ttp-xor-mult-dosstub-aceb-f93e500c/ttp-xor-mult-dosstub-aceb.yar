rule TTP_XOR_MULT_DOSStub_aceb {
  strings:
    $key_aceb = { f8 83 [2] 8c 9b [2] cb 99 [2] 8c 88 [2] c2 84 [2] ce 8e [2] d9 85 [2] c2 cb [2] ff }

  condition:
    any of them
}