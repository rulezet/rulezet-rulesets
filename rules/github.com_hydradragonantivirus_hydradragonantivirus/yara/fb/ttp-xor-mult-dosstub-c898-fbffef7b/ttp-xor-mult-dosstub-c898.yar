rule TTP_XOR_MULT_DOSStub_c898 {
  strings:
    $key_c898 = { 9c f0 [2] e8 e8 [2] af ea [2] e8 fb [2] a6 f7 [2] aa fd [2] bd f6 [2] a6 b8 [2] 9b }

  condition:
    any of them
}