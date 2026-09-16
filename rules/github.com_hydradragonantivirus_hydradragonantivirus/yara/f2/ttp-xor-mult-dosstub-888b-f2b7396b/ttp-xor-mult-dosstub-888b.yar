rule TTP_XOR_MULT_DOSStub_888b {
  strings:
    $key_888b = { dc e3 [2] a8 fb [2] ef f9 [2] a8 e8 [2] e6 e4 [2] ea ee [2] fd e5 [2] e6 ab [2] db }

  condition:
    any of them
}