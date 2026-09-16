rule TTP_XOR_MULT_DOSStub_ab74 {
  strings:
    $key_ab74 = { ff 1c [2] 8b 04 [2] cc 06 [2] 8b 17 [2] c5 1b [2] c9 11 [2] de 1a [2] c5 54 [2] f8 }

  condition:
    any of them
}