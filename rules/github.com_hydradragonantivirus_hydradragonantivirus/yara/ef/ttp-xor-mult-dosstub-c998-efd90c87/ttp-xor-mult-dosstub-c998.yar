rule TTP_XOR_MULT_DOSStub_c998 {
  strings:
    $key_c998 = { 9d f0 [2] e9 e8 [2] ae ea [2] e9 fb [2] a7 f7 [2] ab fd [2] bc f6 [2] a7 b8 [2] 9a }

  condition:
    any of them
}