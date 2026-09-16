rule TTP_XOR_MULT_DOSStub_4b8f {
  strings:
    $key_4b8f = { 1f e7 [2] 6b ff [2] 2c fd [2] 6b ec [2] 25 e0 [2] 29 ea [2] 3e e1 [2] 25 af [2] 18 }

  condition:
    any of them
}