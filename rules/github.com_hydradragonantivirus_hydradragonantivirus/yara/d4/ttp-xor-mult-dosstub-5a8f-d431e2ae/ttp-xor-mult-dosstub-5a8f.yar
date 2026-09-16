rule TTP_XOR_MULT_DOSStub_5a8f {
  strings:
    $key_5a8f = { 0e e7 [2] 7a ff [2] 3d fd [2] 7a ec [2] 34 e0 [2] 38 ea [2] 2f e1 [2] 34 af [2] 09 }

  condition:
    any of them
}