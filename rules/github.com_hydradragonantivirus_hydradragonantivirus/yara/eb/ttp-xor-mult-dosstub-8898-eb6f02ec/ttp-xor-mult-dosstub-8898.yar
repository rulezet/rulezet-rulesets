rule TTP_XOR_MULT_DOSStub_8898 {
  strings:
    $key_8898 = { dc f0 [2] a8 e8 [2] ef ea [2] a8 fb [2] e6 f7 [2] ea fd [2] fd f6 [2] e6 b8 [2] db }

  condition:
    any of them
}