rule TTP_XOR_MULT_DOSStub_038b {
  strings:
    $key_038b = { 57 e3 [2] 23 fb [2] 64 f9 [2] 23 e8 [2] 6d e4 [2] 61 ee [2] 76 e5 [2] 6d ab [2] 50 }

  condition:
    any of them
}