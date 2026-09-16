rule TTP_XOR_MULT_DOSStub_388f {
  strings:
    $key_388f = { 6c e7 [2] 18 ff [2] 5f fd [2] 18 ec [2] 56 e0 [2] 5a ea [2] 4d e1 [2] 56 af [2] 6b }

  condition:
    any of them
}