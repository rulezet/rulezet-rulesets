rule TTP_XOR_MULT_DOSStub_a5fd {
  strings:
    $key_a5fd = { f1 95 [2] 85 8d [2] c2 8f [2] 85 9e [2] cb 92 [2] c7 98 [2] d0 93 [2] cb dd [2] f6 }

  condition:
    any of them
}