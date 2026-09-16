rule TTP_XOR_MULT_DOSStub_278f {
  strings:
    $key_278f = { 73 e7 [2] 07 ff [2] 40 fd [2] 07 ec [2] 49 e0 [2] 45 ea [2] 52 e1 [2] 49 af [2] 74 }

  condition:
    any of them
}