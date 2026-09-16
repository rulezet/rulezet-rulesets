rule TTP_XOR_MULT_DOSStub_5d8f {
  strings:
    $key_5d8f = { 09 e7 [2] 7d ff [2] 3a fd [2] 7d ec [2] 33 e0 [2] 3f ea [2] 28 e1 [2] 33 af [2] 0e }

  condition:
    any of them
}