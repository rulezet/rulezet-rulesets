rule TTP_XOR_MULT_DOSStub_a506 {
  strings:
    $key_a506 = { f1 6e [2] 85 76 [2] c2 74 [2] 85 65 [2] cb 69 [2] c7 63 [2] d0 68 [2] cb 26 [2] f6 }

  condition:
    any of them
}