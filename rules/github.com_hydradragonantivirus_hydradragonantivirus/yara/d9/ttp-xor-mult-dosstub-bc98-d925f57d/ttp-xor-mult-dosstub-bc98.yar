rule TTP_XOR_MULT_DOSStub_bc98 {
  strings:
    $key_bc98 = { e8 f0 [2] 9c e8 [2] db ea [2] 9c fb [2] d2 f7 [2] de fd [2] c9 f6 [2] d2 b8 [2] ef }

  condition:
    any of them
}