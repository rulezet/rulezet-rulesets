rule TTP_XOR_MULT_DOSStub_778b {
  strings:
    $key_778b = { 23 e3 [2] 57 fb [2] 10 f9 [2] 57 e8 [2] 19 e4 [2] 15 ee [2] 02 e5 [2] 19 ab [2] 24 }

  condition:
    any of them
}