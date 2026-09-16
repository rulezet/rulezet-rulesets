rule TTP_XOR_MULT_DOSStub_6c8b {
  strings:
    $key_6c8b = { 38 e3 [2] 4c fb [2] 0b f9 [2] 4c e8 [2] 02 e4 [2] 0e ee [2] 19 e5 [2] 02 ab [2] 3f }

  condition:
    any of them
}