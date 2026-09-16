rule TTP_XOR_MULT_DOSStub_abe3 {
  strings:
    $key_abe3 = { ff 8b [2] 8b 93 [2] cc 91 [2] 8b 80 [2] c5 8c [2] c9 86 [2] de 8d [2] c5 c3 [2] f8 }

  condition:
    any of them
}