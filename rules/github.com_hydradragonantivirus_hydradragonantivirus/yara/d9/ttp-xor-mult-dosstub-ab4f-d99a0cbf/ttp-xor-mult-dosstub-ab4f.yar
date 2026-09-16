rule TTP_XOR_MULT_DOSStub_ab4f {
  strings:
    $key_ab4f = { ff 27 [2] 8b 3f [2] cc 3d [2] 8b 2c [2] c5 20 [2] c9 2a [2] de 21 [2] c5 6f [2] f8 }

  condition:
    any of them
}