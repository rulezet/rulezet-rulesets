rule TTP_XOR_MULT_DOSStub_a51e {
  strings:
    $key_a51e = { f1 76 [2] 85 6e [2] c2 6c [2] 85 7d [2] cb 71 [2] c7 7b [2] d0 70 [2] cb 3e [2] f6 }

  condition:
    any of them
}