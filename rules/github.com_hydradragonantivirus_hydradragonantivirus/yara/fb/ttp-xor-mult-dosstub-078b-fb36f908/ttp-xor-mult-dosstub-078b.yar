rule TTP_XOR_MULT_DOSStub_078b {
  strings:
    $key_078b = { 53 e3 [2] 27 fb [2] 60 f9 [2] 27 e8 [2] 69 e4 [2] 65 ee [2] 72 e5 [2] 69 ab [2] 54 }

  condition:
    any of them
}