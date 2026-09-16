rule TTP_XOR_MULT_DOSStub_a164 {
  strings:
    $key_a164 = { f5 0c [2] 81 14 [2] c6 16 [2] 81 07 [2] cf 0b [2] c3 01 [2] d4 0a [2] cf 44 [2] f2 }

  condition:
    any of them
}