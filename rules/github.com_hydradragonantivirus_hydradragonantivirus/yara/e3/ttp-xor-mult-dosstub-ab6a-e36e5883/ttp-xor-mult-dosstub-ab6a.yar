rule TTP_XOR_MULT_DOSStub_ab6a {
  strings:
    $key_ab6a = { ff 02 [2] 8b 1a [2] cc 18 [2] 8b 09 [2] c5 05 [2] c9 0f [2] de 04 [2] c5 4a [2] f8 }

  condition:
    any of them
}