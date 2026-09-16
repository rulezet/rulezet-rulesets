rule TTP_XOR_MULT_DOSStub_a539 {
  strings:
    $key_a539 = { f1 51 [2] 85 49 [2] c2 4b [2] 85 5a [2] cb 56 [2] c7 5c [2] d0 57 [2] cb 19 [2] f6 }

  condition:
    any of them
}