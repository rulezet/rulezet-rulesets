rule TTP_XOR_MULT_DOSStub_88bc {
  strings:
    $key_88bc = { dc d4 [2] a8 cc [2] ef ce [2] a8 df [2] e6 d3 [2] ea d9 [2] fd d2 [2] e6 9c [2] db }

  condition:
    any of them
}