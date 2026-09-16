rule TTP_XOR_MULT_DOSStub_ab4c {
  strings:
    $key_ab4c = { ff 24 [2] 8b 3c [2] cc 3e [2] 8b 2f [2] c5 23 [2] c9 29 [2] de 22 [2] c5 6c [2] f8 }

  condition:
    any of them
}