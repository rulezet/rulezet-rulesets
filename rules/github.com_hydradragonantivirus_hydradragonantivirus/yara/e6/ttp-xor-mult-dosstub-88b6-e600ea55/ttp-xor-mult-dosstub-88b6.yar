rule TTP_XOR_MULT_DOSStub_88b6 {
  strings:
    $key_88b6 = { dc de [2] a8 c6 [2] ef c4 [2] a8 d5 [2] e6 d9 [2] ea d3 [2] fd d8 [2] e6 96 [2] db }

  condition:
    any of them
}