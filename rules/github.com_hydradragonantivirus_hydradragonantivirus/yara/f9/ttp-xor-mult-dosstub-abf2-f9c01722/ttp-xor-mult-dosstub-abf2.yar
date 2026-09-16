rule TTP_XOR_MULT_DOSStub_abf2 {
  strings:
    $key_abf2 = { ff 9a [2] 8b 82 [2] cc 80 [2] 8b 91 [2] c5 9d [2] c9 97 [2] de 9c [2] c5 d2 [2] f8 }

  condition:
    any of them
}