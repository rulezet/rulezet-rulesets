rule TTP_XOR_MULT_DOSStub_588f {
  strings:
    $key_588f = { 0c e7 [2] 78 ff [2] 3f fd [2] 78 ec [2] 36 e0 [2] 3a ea [2] 2d e1 [2] 36 af [2] 0b }

  condition:
    any of them
}