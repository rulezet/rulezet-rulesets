rule TTP_XOR_MULT_DOSStub_448b {
  strings:
    $key_448b = { 10 e3 [2] 64 fb [2] 23 f9 [2] 64 e8 [2] 2a e4 [2] 26 ee [2] 31 e5 [2] 2a ab [2] 17 }

  condition:
    any of them
}