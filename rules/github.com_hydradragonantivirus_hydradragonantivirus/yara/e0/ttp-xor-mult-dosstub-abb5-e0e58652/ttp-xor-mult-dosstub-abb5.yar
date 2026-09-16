rule TTP_XOR_MULT_DOSStub_abb5 {
  strings:
    $key_abb5 = { ff dd [2] 8b c5 [2] cc c7 [2] 8b d6 [2] c5 da [2] c9 d0 [2] de db [2] c5 95 [2] f8 }

  condition:
    any of them
}