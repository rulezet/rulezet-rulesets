rule TTP_XOR_MULT_DOSStub_ab1e {
  strings:
    $key_ab1e = { ff 76 [2] 8b 6e [2] cc 6c [2] 8b 7d [2] c5 71 [2] c9 7b [2] de 70 [2] c5 3e [2] f8 }

  condition:
    any of them
}