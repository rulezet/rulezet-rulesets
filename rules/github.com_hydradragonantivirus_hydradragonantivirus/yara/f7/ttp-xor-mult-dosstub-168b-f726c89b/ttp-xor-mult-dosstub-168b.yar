rule TTP_XOR_MULT_DOSStub_168b {
  strings:
    $key_168b = { 42 e3 [2] 36 fb [2] 71 f9 [2] 36 e8 [2] 78 e4 [2] 74 ee [2] 63 e5 [2] 78 ab [2] 45 }

  condition:
    any of them
}