rule TTP_XOR_MULT_DOSStub_dabc {
  strings:
    $key_dabc = { 8e d4 [2] fa cc [2] bd ce [2] fa df [2] b4 d3 [2] b8 d9 [2] af d2 [2] b4 9c [2] 89 }

  condition:
    any of them
}