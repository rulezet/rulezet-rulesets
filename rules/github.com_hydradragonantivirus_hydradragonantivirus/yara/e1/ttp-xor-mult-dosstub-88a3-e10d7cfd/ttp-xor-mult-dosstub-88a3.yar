rule TTP_XOR_MULT_DOSStub_88a3 {
  strings:
    $key_88a3 = { dc cb [2] a8 d3 [2] ef d1 [2] a8 c0 [2] e6 cc [2] ea c6 [2] fd cd [2] e6 83 [2] db }

  condition:
    any of them
}