rule TTP_XOR_MULT_DOSStub_728f {
  strings:
    $key_728f = { 26 e7 [2] 52 ff [2] 15 fd [2] 52 ec [2] 1c e0 [2] 10 ea [2] 07 e1 [2] 1c af [2] 21 }

  condition:
    any of them
}