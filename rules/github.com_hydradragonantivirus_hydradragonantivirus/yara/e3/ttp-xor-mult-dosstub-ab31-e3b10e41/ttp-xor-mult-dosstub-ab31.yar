rule TTP_XOR_MULT_DOSStub_ab31 {
  strings:
    $key_ab31 = { ff 59 [2] 8b 41 [2] cc 43 [2] 8b 52 [2] c5 5e [2] c9 54 [2] de 5f [2] c5 11 [2] f8 }

  condition:
    any of them
}