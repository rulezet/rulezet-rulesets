rule TTP_XOR_MULT_DOSStub_3d8b {
  strings:
    $key_3d8b = { 69 e3 [2] 1d fb [2] 5a f9 [2] 1d e8 [2] 53 e4 [2] 5f ee [2] 48 e5 [2] 53 ab [2] 6e }

  condition:
    any of them
}