rule TTP_XOR_MULT_DOSStub_0b8f {
  strings:
    $key_0b8f = { 5f e7 [2] 2b ff [2] 6c fd [2] 2b ec [2] 65 e0 [2] 69 ea [2] 7e e1 [2] 65 af [2] 58 }

  condition:
    any of them
}