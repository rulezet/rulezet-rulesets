rule TTP_XOR_MULT_DOSStub_088f {
  strings:
    $key_088f = { 5c e7 [2] 28 ff [2] 6f fd [2] 28 ec [2] 66 e0 [2] 6a ea [2] 7d e1 [2] 66 af [2] 5b }

  condition:
    any of them
}