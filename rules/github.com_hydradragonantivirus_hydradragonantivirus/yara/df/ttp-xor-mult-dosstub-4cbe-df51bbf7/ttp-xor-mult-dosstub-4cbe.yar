rule TTP_XOR_MULT_DOSStub_4cbe {
  strings:
    $key_4cbe = { 18 d6 [2] 6c ce [2] 2b cc [2] 6c dd [2] 22 d1 [2] 2e db [2] 39 d0 [2] 22 9e [2] 1f }

  condition:
    any of them
}