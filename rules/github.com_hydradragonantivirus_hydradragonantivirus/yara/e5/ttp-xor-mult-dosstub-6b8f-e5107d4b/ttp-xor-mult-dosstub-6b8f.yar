rule TTP_XOR_MULT_DOSStub_6b8f {
  strings:
    $key_6b8f = { 3f e7 [2] 4b ff [2] 0c fd [2] 4b ec [2] 05 e0 [2] 09 ea [2] 1e e1 [2] 05 af [2] 38 }

  condition:
    any of them
}