rule TTP_XOR_MULT_DOSStub_ab38 {
  strings:
    $key_ab38 = { ff 50 [2] 8b 48 [2] cc 4a [2] 8b 5b [2] c5 57 [2] c9 5d [2] de 56 [2] c5 18 [2] f8 }

  condition:
    any of them
}