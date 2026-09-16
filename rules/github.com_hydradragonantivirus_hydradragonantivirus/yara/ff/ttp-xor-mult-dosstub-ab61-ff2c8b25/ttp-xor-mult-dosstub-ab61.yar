rule TTP_XOR_MULT_DOSStub_ab61 {
  strings:
    $key_ab61 = { ff 09 [2] 8b 11 [2] cc 13 [2] 8b 02 [2] c5 0e [2] c9 04 [2] de 0f [2] c5 41 [2] f8 }

  condition:
    any of them
}