rule TTP_XOR_MULT_DOSStub_398b {
  strings:
    $key_398b = { 6d e3 [2] 19 fb [2] 5e f9 [2] 19 e8 [2] 57 e4 [2] 5b ee [2] 4c e5 [2] 57 ab [2] 6a }

  condition:
    any of them
}