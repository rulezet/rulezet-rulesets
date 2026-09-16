rule TTP_XOR_MULT_DOSStub_ab78 {
  strings:
    $key_ab78 = { ff 10 [2] 8b 08 [2] cc 0a [2] 8b 1b [2] c5 17 [2] c9 1d [2] de 16 [2] c5 58 [2] f8 }

  condition:
    any of them
}