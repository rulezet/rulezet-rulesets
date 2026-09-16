rule TTP_XOR_MULT_DOSStub_ab47 {
  strings:
    $key_ab47 = { ff 2f [2] 8b 37 [2] cc 35 [2] 8b 24 [2] c5 28 [2] c9 22 [2] de 29 [2] c5 67 [2] f8 }

  condition:
    any of them
}