rule TTP_XOR_MULT_DOSStub_168f {
  strings:
    $key_168f = { 42 e7 [2] 36 ff [2] 71 fd [2] 36 ec [2] 78 e0 [2] 74 ea [2] 63 e1 [2] 78 af [2] 45 }

  condition:
    any of them
}