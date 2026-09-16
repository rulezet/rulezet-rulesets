rule TTP_XOR_MULT_DOSStub_ab0b {
  strings:
    $key_ab0b = { ff 63 [2] 8b 7b [2] cc 79 [2] 8b 68 [2] c5 64 [2] c9 6e [2] de 65 [2] c5 2b [2] f8 }

  condition:
    any of them
}