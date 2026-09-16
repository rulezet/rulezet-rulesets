rule TTP_XOR_MULT_DOSStub_88bb {
  strings:
    $key_88bb = { dc d3 [2] a8 cb [2] ef c9 [2] a8 d8 [2] e6 d4 [2] ea de [2] fd d5 [2] e6 9b [2] db }

  condition:
    any of them
}