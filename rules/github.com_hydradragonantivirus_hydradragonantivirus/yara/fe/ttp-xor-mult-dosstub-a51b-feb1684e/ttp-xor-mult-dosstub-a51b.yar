rule TTP_XOR_MULT_DOSStub_a51b {
  strings:
    $key_a51b = { f1 73 [2] 85 6b [2] c2 69 [2] 85 78 [2] cb 74 [2] c7 7e [2] d0 75 [2] cb 3b [2] f6 }

  condition:
    any of them
}