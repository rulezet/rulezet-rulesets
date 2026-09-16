rule TTP_XOR_MULT_DOSStub_358f {
  strings:
    $key_358f = { 61 e7 [2] 15 ff [2] 52 fd [2] 15 ec [2] 5b e0 [2] 57 ea [2] 40 e1 [2] 5b af [2] 66 }

  condition:
    any of them
}