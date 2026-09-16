rule TTP_XOR_MULT_DOSStub_abb9 {
  strings:
    $key_abb9 = { ff d1 [2] 8b c9 [2] cc cb [2] 8b da [2] c5 d6 [2] c9 dc [2] de d7 [2] c5 99 [2] f8 }

  condition:
    any of them
}