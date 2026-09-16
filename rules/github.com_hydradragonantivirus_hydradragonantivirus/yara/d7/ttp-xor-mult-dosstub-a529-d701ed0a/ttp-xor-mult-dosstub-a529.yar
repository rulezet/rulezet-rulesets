rule TTP_XOR_MULT_DOSStub_a529 {
  strings:
    $key_a529 = { f1 41 [2] 85 59 [2] c2 5b [2] 85 4a [2] cb 46 [2] c7 4c [2] d0 47 [2] cb 09 [2] f6 }

  condition:
    any of them
}