rule TTP_XOR_MULT_DOSStub_f38f {
  strings:
    $key_f38f = { a7 e7 [2] d3 ff [2] 94 fd [2] d3 ec [2] 9d e0 [2] 91 ea [2] 86 e1 [2] 9d af [2] a0 }

  condition:
    any of them
}