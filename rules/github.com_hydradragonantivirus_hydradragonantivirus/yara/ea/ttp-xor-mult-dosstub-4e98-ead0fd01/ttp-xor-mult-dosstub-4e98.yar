rule TTP_XOR_MULT_DOSStub_4e98 {
  strings:
    $key_4e98 = { 1a f0 [2] 6e e8 [2] 29 ea [2] 6e fb [2] 20 f7 [2] 2c fd [2] 3b f6 [2] 20 b8 [2] 1d }

  condition:
    any of them
}