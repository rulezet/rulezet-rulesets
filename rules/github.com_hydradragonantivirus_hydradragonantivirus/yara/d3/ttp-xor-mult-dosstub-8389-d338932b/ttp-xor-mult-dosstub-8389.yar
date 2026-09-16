rule TTP_XOR_MULT_DOSStub_8389 {
  strings:
    $key_8389 = { d7 e1 [2] a3 f9 [2] e4 fb [2] a3 ea [2] ed e6 [2] e1 ec [2] f6 e7 [2] ed a9 [2] d0 }

  condition:
    any of them
}