rule TTP_XOR_MULT_DOSStub_288f {
  strings:
    $key_288f = { 7c e7 [2] 08 ff [2] 4f fd [2] 08 ec [2] 46 e0 [2] 4a ea [2] 5d e1 [2] 46 af [2] 7b }

  condition:
    any of them
}