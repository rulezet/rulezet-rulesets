rule TTP_XOR_MULT_DOSStub_478b {
  strings:
    $key_478b = { 13 e3 [2] 67 fb [2] 20 f9 [2] 67 e8 [2] 29 e4 [2] 25 ee [2] 32 e5 [2] 29 ab [2] 14 }

  condition:
    any of them
}