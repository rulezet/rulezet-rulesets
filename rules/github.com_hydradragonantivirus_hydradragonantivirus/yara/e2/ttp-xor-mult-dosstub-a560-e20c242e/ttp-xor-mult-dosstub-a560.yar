rule TTP_XOR_MULT_DOSStub_a560 {
  strings:
    $key_a560 = { f1 08 [2] 85 10 [2] c2 12 [2] 85 03 [2] cb 0f [2] c7 05 [2] d0 0e [2] cb 40 [2] f6 }

  condition:
    any of them
}