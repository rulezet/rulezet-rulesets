rule TTP_XOR_MULT_DOSStub_648b {
  strings:
    $key_648b = { 30 e3 [2] 44 fb [2] 03 f9 [2] 44 e8 [2] 0a e4 [2] 06 ee [2] 11 e5 [2] 0a ab [2] 37 }

  condition:
    any of them
}