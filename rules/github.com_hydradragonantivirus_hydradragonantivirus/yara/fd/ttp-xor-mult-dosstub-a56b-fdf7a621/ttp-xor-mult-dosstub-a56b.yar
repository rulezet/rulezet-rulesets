rule TTP_XOR_MULT_DOSStub_a56b {
  strings:
    $key_a56b = { f1 03 [2] 85 1b [2] c2 19 [2] 85 08 [2] cb 04 [2] c7 0e [2] d0 05 [2] cb 4b [2] f6 }

  condition:
    any of them
}