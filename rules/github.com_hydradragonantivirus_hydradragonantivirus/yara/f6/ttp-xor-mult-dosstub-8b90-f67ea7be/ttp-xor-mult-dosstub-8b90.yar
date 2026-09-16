rule TTP_XOR_MULT_DOSStub_8b90 {
  strings:
    $key_8b90 = { df f8 [2] ab e0 [2] ec e2 [2] ab f3 [2] e5 ff [2] e9 f5 [2] fe fe [2] e5 b0 [2] d8 }

  condition:
    any of them
}