rule TTP_XOR_MULT_DOSStub_628f {
  strings:
    $key_628f = { 36 e7 [2] 42 ff [2] 05 fd [2] 42 ec [2] 0c e0 [2] 00 ea [2] 17 e1 [2] 0c af [2] 31 }

  condition:
    any of them
}