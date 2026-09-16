rule TTP_XOR_MULT_DOSStub_5c8b {
  strings:
    $key_5c8b = { 08 e3 [2] 7c fb [2] 3b f9 [2] 7c e8 [2] 32 e4 [2] 3e ee [2] 29 e5 [2] 32 ab [2] 0f }

  condition:
    any of them
}