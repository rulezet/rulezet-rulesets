rule TTP_XOR_MULT_DOSStub_ab0e {
  strings:
    $key_ab0e = { ff 66 [2] 8b 7e [2] cc 7c [2] 8b 6d [2] c5 61 [2] c9 6b [2] de 60 [2] c5 2e [2] f8 }

  condition:
    any of them
}