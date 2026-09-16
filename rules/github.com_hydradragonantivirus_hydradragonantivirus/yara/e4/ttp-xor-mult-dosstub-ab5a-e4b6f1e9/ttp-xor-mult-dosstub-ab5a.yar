rule TTP_XOR_MULT_DOSStub_ab5a {
  strings:
    $key_ab5a = { ff 32 [2] 8b 2a [2] cc 28 [2] 8b 39 [2] c5 35 [2] c9 3f [2] de 34 [2] c5 7a [2] f8 }

  condition:
    any of them
}