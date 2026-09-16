rule TTP_XOR_MULT_DOSStub_ab5d {
  strings:
    $key_ab5d = { ff 35 [2] 8b 2d [2] cc 2f [2] 8b 3e [2] c5 32 [2] c9 38 [2] de 33 [2] c5 7d [2] f8 }

  condition:
    any of them
}