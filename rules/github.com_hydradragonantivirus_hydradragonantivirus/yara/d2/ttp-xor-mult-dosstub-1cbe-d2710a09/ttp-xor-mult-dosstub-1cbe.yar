rule TTP_XOR_MULT_DOSStub_1cbe {
  strings:
    $key_1cbe = { 48 d6 [2] 3c ce [2] 7b cc [2] 3c dd [2] 72 d1 [2] 7e db [2] 69 d0 [2] 72 9e [2] 4f }

  condition:
    any of them
}