rule TTP_XOR_MULT_DOSStub_ab30 {
  strings:
    $key_ab30 = { ff 58 [2] 8b 40 [2] cc 42 [2] 8b 53 [2] c5 5f [2] c9 55 [2] de 5e [2] c5 10 [2] f8 }

  condition:
    any of them
}