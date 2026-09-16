rule TTP_XOR_MULT_DOSStub_a5f9 {
  strings:
    $key_a5f9 = { f1 91 [2] 85 89 [2] c2 8b [2] 85 9a [2] cb 96 [2] c7 9c [2] d0 97 [2] cb d9 [2] f6 }

  condition:
    any of them
}