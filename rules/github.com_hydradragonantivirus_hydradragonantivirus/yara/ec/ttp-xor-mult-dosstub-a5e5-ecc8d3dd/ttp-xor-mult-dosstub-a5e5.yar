rule TTP_XOR_MULT_DOSStub_a5e5 {
  strings:
    $key_a5e5 = { f1 8d [2] 85 95 [2] c2 97 [2] 85 86 [2] cb 8a [2] c7 80 [2] d0 8b [2] cb c5 [2] f6 }

  condition:
    any of them
}