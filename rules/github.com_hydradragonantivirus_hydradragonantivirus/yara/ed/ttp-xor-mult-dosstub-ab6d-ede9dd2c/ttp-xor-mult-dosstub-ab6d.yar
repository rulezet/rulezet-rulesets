rule TTP_XOR_MULT_DOSStub_ab6d {
  strings:
    $key_ab6d = { ff 05 [2] 8b 1d [2] cc 1f [2] 8b 0e [2] c5 02 [2] c9 08 [2] de 03 [2] c5 4d [2] f8 }

  condition:
    any of them
}