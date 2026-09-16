rule TTP_XOR_MULT_DOSStub_5e98 {
  strings:
    $key_5e98 = { 0a f0 [2] 7e e8 [2] 39 ea [2] 7e fb [2] 30 f7 [2] 3c fd [2] 2b f6 [2] 30 b8 [2] 0d }

  condition:
    any of them
}