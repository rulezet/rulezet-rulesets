rule TTP_XOR_MULT_DOSStub_2cbc {
  strings:
    $key_2cbc = { 78 d4 [2] 0c cc [2] 4b ce [2] 0c df [2] 42 d3 [2] 4e d9 [2] 59 d2 [2] 42 9c [2] 7f }

  condition:
    any of them
}