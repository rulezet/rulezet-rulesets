rule TTP_XOR_MULT_DOSStub_3c8b {
  strings:
    $key_3c8b = { 68 e3 [2] 1c fb [2] 5b f9 [2] 1c e8 [2] 52 e4 [2] 5e ee [2] 49 e5 [2] 52 ab [2] 6f }

  condition:
    any of them
}