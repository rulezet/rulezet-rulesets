rule TTP_XOR_MULT_DOSStub_e38f {
  strings:
    $key_e38f = { b7 e7 [2] c3 ff [2] 84 fd [2] c3 ec [2] 8d e0 [2] 81 ea [2] 96 e1 [2] 8d af [2] b0 }

  condition:
    any of them
}