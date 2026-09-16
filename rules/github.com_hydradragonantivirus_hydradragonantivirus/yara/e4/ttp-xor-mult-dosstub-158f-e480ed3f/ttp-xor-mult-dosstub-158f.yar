rule TTP_XOR_MULT_DOSStub_158f {
  strings:
    $key_158f = { 41 e7 [2] 35 ff [2] 72 fd [2] 35 ec [2] 7b e0 [2] 77 ea [2] 60 e1 [2] 7b af [2] 46 }

  condition:
    any of them
}