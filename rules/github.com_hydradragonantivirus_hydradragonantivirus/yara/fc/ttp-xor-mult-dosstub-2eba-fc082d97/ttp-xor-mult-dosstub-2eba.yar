rule TTP_XOR_MULT_DOSStub_2eba {
  strings:
    $key_2eba = { 7a d2 [2] 0e ca [2] 49 c8 [2] 0e d9 [2] 40 d5 [2] 4c df [2] 5b d4 [2] 40 9a [2] 7d }

  condition:
    any of them
}