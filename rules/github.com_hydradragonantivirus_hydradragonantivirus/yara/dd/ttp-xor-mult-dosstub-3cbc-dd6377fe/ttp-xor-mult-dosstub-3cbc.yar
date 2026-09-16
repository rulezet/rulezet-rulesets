rule TTP_XOR_MULT_DOSStub_3cbc {
  strings:
    $key_3cbc = { 68 d4 [2] 1c cc [2] 5b ce [2] 1c df [2] 52 d3 [2] 5e d9 [2] 49 d2 [2] 52 9c [2] 6f }

  condition:
    any of them
}