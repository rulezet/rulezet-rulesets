rule TTP_XOR_MULT_DOSStub_738f {
  strings:
    $key_738f = { 27 e7 [2] 53 ff [2] 14 fd [2] 53 ec [2] 1d e0 [2] 11 ea [2] 06 e1 [2] 1d af [2] 20 }

  condition:
    any of them
}