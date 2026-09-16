rule TTP_XOR_MULT_DOSStub_abf7 {
  strings:
    $key_abf7 = { ff 9f [2] 8b 87 [2] cc 85 [2] 8b 94 [2] c5 98 [2] c9 92 [2] de 99 [2] c5 d7 [2] f8 }

  condition:
    any of them
}