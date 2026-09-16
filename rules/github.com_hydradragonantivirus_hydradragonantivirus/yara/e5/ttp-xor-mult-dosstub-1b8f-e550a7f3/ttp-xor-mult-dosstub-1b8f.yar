rule TTP_XOR_MULT_DOSStub_1b8f {
  strings:
    $key_1b8f = { 4f e7 [2] 3b ff [2] 7c fd [2] 3b ec [2] 75 e0 [2] 79 ea [2] 6e e1 [2] 75 af [2] 48 }

  condition:
    any of them
}