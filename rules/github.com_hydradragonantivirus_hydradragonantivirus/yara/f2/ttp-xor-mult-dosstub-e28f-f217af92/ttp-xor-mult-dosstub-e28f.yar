rule TTP_XOR_MULT_DOSStub_e28f {
  strings:
    $key_e28f = { b6 e7 [2] c2 ff [2] 85 fd [2] c2 ec [2] 8c e0 [2] 80 ea [2] 97 e1 [2] 8c af [2] b1 }

  condition:
    any of them
}