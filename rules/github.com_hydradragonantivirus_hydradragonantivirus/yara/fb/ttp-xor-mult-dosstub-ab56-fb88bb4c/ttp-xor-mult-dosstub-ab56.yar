rule TTP_XOR_MULT_DOSStub_ab56 {
  strings:
    $key_ab56 = { ff 3e [2] 8b 26 [2] cc 24 [2] 8b 35 [2] c5 39 [2] c9 33 [2] de 38 [2] c5 76 [2] f8 }

  condition:
    any of them
}