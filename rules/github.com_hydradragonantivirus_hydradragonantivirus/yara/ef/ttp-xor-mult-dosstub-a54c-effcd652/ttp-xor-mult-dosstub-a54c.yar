rule TTP_XOR_MULT_DOSStub_a54c {
  strings:
    $key_a54c = { f1 24 [2] 85 3c [2] c2 3e [2] 85 2f [2] cb 23 [2] c7 29 [2] d0 22 [2] cb 6c [2] f6 }

  condition:
    any of them
}