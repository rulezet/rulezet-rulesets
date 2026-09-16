rule TTP_XOR_MULT_DOSStub_859c {
  strings:
    $key_859c = { d1 f4 [2] a5 ec [2] e2 ee [2] a5 ff [2] eb f3 [2] e7 f9 [2] f0 f2 [2] eb bc [2] d6 }

  condition:
    any of them
}