rule TTP_XOR_MULT_DOSStub_0e8b {
  strings:
    $key_0e8b = { 5a e3 [2] 2e fb [2] 69 f9 [2] 2e e8 [2] 60 e4 [2] 6c ee [2] 7b e5 [2] 60 ab [2] 5d }

  condition:
    any of them
}