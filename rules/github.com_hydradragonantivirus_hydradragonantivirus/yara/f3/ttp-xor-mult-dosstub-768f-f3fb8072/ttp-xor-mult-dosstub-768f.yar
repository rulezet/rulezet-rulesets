rule TTP_XOR_MULT_DOSStub_768f {
  strings:
    $key_768f = { 22 e7 [2] 56 ff [2] 11 fd [2] 56 ec [2] 18 e0 [2] 14 ea [2] 03 e1 [2] 18 af [2] 25 }

  condition:
    any of them
}