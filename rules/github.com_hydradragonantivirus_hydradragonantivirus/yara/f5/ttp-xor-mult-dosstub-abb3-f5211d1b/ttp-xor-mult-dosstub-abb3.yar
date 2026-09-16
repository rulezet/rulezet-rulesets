rule TTP_XOR_MULT_DOSStub_abb3 {
  strings:
    $key_abb3 = { ff db [2] 8b c3 [2] cc c1 [2] 8b d0 [2] c5 dc [2] c9 d6 [2] de dd [2] c5 93 [2] f8 }

  condition:
    any of them
}