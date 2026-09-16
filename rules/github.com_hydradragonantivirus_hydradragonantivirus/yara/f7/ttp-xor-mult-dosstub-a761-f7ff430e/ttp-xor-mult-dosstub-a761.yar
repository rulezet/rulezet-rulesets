rule TTP_XOR_MULT_DOSStub_a761 {
  strings:
    $key_a761 = { f3 09 [2] 87 11 [2] c0 13 [2] 87 02 [2] c9 0e [2] c5 04 [2] d2 0f [2] c9 41 [2] f4 }

  condition:
    any of them
}