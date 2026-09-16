rule TTP_XOR_MULT_DOSStub_1a93 {
  strings:
    $key_1a93 = { 4e fb [2] 3a e3 [2] 7d e1 [2] 3a f0 [2] 74 fc [2] 78 f6 [2] 6f fd [2] 74 b3 [2] 49 }

  condition:
    any of them
}