rule TTP_XOR_MULT_DOSStub_188b {
  strings:
    $key_188b = { 4c e3 [2] 38 fb [2] 7f f9 [2] 38 e8 [2] 76 e4 [2] 7a ee [2] 6d e5 [2] 76 ab [2] 4b }

  condition:
    any of them
}