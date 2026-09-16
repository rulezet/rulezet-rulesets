rule TTP_XOR_MULT_DOSStub_ab79 {
  strings:
    $key_ab79 = { ff 11 [2] 8b 09 [2] cc 0b [2] 8b 1a [2] c5 16 [2] c9 1c [2] de 17 [2] c5 59 [2] f8 }

  condition:
    any of them
}