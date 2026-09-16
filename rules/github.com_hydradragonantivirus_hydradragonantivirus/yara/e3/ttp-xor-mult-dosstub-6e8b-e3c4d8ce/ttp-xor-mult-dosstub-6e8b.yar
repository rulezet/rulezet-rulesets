rule TTP_XOR_MULT_DOSStub_6e8b {
  strings:
    $key_6e8b = { 3a e3 [2] 4e fb [2] 09 f9 [2] 4e e8 [2] 00 e4 [2] 0c ee [2] 1b e5 [2] 00 ab [2] 3d }

  condition:
    any of them
}