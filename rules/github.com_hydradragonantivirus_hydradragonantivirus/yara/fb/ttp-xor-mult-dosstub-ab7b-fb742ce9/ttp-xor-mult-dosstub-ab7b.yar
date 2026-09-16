rule TTP_XOR_MULT_DOSStub_ab7b {
  strings:
    $key_ab7b = { ff 13 [2] 8b 0b [2] cc 09 [2] 8b 18 [2] c5 14 [2] c9 1e [2] de 15 [2] c5 5b [2] f8 }

  condition:
    any of them
}