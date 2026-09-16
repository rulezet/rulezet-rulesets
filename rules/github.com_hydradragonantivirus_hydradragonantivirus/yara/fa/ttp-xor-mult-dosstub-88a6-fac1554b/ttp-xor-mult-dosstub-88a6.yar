rule TTP_XOR_MULT_DOSStub_88a6 {
  strings:
    $key_88a6 = { dc ce [2] a8 d6 [2] ef d4 [2] a8 c5 [2] e6 c9 [2] ea c3 [2] fd c8 [2] e6 86 [2] db }

  condition:
    any of them
}