rule TTP_XOR_MULT_DOSStub_abbb {
  strings:
    $key_abbb = { ff d3 [2] 8b cb [2] cc c9 [2] 8b d8 [2] c5 d4 [2] c9 de [2] de d5 [2] c5 9b [2] f8 }

  condition:
    any of them
}