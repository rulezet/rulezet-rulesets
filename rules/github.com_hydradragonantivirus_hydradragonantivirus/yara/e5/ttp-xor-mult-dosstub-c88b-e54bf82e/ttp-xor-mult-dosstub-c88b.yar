rule TTP_XOR_MULT_DOSStub_c88b {
  strings:
    $key_c88b = { 9c e3 [2] e8 fb [2] af f9 [2] e8 e8 [2] a6 e4 [2] aa ee [2] bd e5 [2] a6 ab [2] 9b }

  condition:
    any of them
}