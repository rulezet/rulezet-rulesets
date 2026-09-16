rule TTP_XOR_MULT_DOSStub_2a93 {
  strings:
    $key_2a93 = { 7e fb [2] 0a e3 [2] 4d e1 [2] 0a f0 [2] 44 fc [2] 48 f6 [2] 5f fd [2] 44 b3 [2] 79 }

  condition:
    any of them
}