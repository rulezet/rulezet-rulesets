rule TTP_XOR_MULT_DOSStub_a4f5 {
  strings:
    $key_a4f5 = { f0 9d [2] 84 85 [2] c3 87 [2] 84 96 [2] ca 9a [2] c6 90 [2] d1 9b [2] ca d5 [2] f7 }

  condition:
    any of them
}