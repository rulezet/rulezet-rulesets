rule TTP_XOR_MULT_DOSStub_548b {
  strings:
    $key_548b = { 00 e3 [2] 74 fb [2] 33 f9 [2] 74 e8 [2] 3a e4 [2] 36 ee [2] 21 e5 [2] 3a ab [2] 07 }

  condition:
    any of them
}