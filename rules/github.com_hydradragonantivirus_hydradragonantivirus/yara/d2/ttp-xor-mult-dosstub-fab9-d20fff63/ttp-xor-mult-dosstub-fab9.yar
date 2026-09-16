rule TTP_XOR_MULT_DOSStub_fab9 {
  strings:
    $key_fab9 = { ae d1 [2] da c9 [2] 9d cb [2] da da [2] 94 d6 [2] 98 dc [2] 8f d7 [2] 94 99 [2] a9 }

  condition:
    any of them
}