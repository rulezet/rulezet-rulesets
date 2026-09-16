rule TTP_XOR_MULT_DOSStub_5a93 {
  strings:
    $key_5a93 = { 0e fb [2] 7a e3 [2] 3d e1 [2] 7a f0 [2] 34 fc [2] 38 f6 [2] 2f fd [2] 34 b3 [2] 09 }

  condition:
    any of them
}