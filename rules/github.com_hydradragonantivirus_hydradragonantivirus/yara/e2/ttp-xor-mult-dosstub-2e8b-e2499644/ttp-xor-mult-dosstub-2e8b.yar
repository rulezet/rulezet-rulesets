rule TTP_XOR_MULT_DOSStub_2e8b {
  strings:
    $key_2e8b = { 7a e3 [2] 0e fb [2] 49 f9 [2] 0e e8 [2] 40 e4 [2] 4c ee [2] 5b e5 [2] 40 ab [2] 7d }

  condition:
    any of them
}