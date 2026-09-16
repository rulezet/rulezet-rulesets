rule TTP_XOR_MULT_DOSStub_88b9 {
  strings:
    $key_88b9 = { dc d1 [2] a8 c9 [2] ef cb [2] a8 da [2] e6 d6 [2] ea dc [2] fd d7 [2] e6 99 [2] db }

  condition:
    any of them
}