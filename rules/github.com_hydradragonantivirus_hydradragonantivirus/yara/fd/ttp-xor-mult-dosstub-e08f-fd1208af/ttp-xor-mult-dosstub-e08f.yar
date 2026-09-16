rule TTP_XOR_MULT_DOSStub_e08f {
  strings:
    $key_e08f = { b4 e7 [2] c0 ff [2] 87 fd [2] c0 ec [2] 8e e0 [2] 82 ea [2] 95 e1 [2] 8e af [2] b3 }

  condition:
    any of them
}