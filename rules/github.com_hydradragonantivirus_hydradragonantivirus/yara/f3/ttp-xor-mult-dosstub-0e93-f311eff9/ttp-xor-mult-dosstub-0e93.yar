rule TTP_XOR_MULT_DOSStub_0e93 {
  strings:
    $key_0e93 = { 5a fb [2] 2e e3 [2] 69 e1 [2] 2e f0 [2] 60 fc [2] 6c f6 [2] 7b fd [2] 60 b3 [2] 5d }

  condition:
    any of them
}