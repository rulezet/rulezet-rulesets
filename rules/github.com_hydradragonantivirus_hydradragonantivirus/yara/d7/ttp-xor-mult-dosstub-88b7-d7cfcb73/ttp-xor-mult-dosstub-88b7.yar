rule TTP_XOR_MULT_DOSStub_88b7 {
  strings:
    $key_88b7 = { dc df [2] a8 c7 [2] ef c5 [2] a8 d4 [2] e6 d8 [2] ea d2 [2] fd d9 [2] e6 97 [2] db }

  condition:
    any of them
}