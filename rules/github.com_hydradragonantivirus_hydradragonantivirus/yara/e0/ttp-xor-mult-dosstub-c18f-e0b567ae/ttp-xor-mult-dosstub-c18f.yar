rule TTP_XOR_MULT_DOSStub_c18f {
  strings:
    $key_c18f = { 95 e7 [2] e1 ff [2] a6 fd [2] e1 ec [2] af e0 [2] a3 ea [2] b4 e1 [2] af af [2] 92 }

  condition:
    any of them
}