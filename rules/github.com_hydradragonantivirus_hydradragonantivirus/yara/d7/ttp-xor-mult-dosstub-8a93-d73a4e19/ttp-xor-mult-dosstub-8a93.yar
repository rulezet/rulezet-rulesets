rule TTP_XOR_MULT_DOSStub_8a93 {
  strings:
    $key_8a93 = { de fb [2] aa e3 [2] ed e1 [2] aa f0 [2] e4 fc [2] e8 f6 [2] ff fd [2] e4 b3 [2] d9 }

  condition:
    any of them
}