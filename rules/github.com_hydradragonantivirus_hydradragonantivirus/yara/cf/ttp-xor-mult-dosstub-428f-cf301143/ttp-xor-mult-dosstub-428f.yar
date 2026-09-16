rule TTP_XOR_MULT_DOSStub_428f {
  strings:
    $key_428f = { 16 e7 [2] 62 ff [2] 25 fd [2] 62 ec [2] 2c e0 [2] 20 ea [2] 37 e1 [2] 2c af [2] 11 }

  condition:
    any of them
}