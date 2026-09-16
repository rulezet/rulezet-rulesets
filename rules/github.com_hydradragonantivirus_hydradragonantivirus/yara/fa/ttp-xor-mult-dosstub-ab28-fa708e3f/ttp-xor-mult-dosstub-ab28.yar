rule TTP_XOR_MULT_DOSStub_ab28 {
  strings:
    $key_ab28 = { ff 40 [2] 8b 58 [2] cc 5a [2] 8b 4b [2] c5 47 [2] c9 4d [2] de 46 [2] c5 08 [2] f8 }

  condition:
    any of them
}