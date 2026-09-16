rule TTP_XOR_MULT_DOSStub_dabb {
  strings:
    $key_dabb = { 8e d3 [2] fa cb [2] bd c9 [2] fa d8 [2] b4 d4 [2] b8 de [2] af d5 [2] b4 9b [2] 89 }

  condition:
    any of them
}