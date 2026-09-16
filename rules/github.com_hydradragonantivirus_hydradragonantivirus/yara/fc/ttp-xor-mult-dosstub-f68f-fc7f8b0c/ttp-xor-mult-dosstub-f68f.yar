rule TTP_XOR_MULT_DOSStub_f68f {
  strings:
    $key_f68f = { a2 e7 [2] d6 ff [2] 91 fd [2] d6 ec [2] 98 e0 [2] 94 ea [2] 83 e1 [2] 98 af [2] a5 }

  condition:
    any of them
}