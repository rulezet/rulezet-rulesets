rule TTP_XOR_MULT_DOSStub_a567 {
  strings:
    $key_a567 = { f1 0f [2] 85 17 [2] c2 15 [2] 85 04 [2] cb 08 [2] c7 02 [2] d0 09 [2] cb 47 [2] f6 }

  condition:
    any of them
}