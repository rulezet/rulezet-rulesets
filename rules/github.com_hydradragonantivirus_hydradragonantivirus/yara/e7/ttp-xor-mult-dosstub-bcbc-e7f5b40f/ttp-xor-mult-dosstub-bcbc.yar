rule TTP_XOR_MULT_DOSStub_bcbc {
  strings:
    $key_bcbc = { e8 d4 [2] 9c cc [2] db ce [2] 9c df [2] d2 d3 [2] de d9 [2] c9 d2 [2] d2 9c [2] ef }

  condition:
    any of them
}