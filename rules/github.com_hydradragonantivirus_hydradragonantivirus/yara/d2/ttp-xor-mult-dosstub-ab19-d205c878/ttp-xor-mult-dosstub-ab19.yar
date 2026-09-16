rule TTP_XOR_MULT_DOSStub_ab19 {
  strings:
    $key_ab19 = { ff 71 [2] 8b 69 [2] cc 6b [2] 8b 7a [2] c5 76 [2] c9 7c [2] de 77 [2] c5 39 [2] f8 }

  condition:
    any of them
}