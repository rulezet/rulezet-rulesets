rule TTP_XOR_MULT_DOSStub_a165 {
  strings:
    $key_a165 = { f5 0d [2] 81 15 [2] c6 17 [2] 81 06 [2] cf 0a [2] c3 00 [2] d4 0b [2] cf 45 [2] f2 }

  condition:
    any of them
}