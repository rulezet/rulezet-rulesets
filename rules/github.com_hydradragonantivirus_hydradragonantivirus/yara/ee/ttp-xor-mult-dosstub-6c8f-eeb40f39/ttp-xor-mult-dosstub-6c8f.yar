rule TTP_XOR_MULT_DOSStub_6c8f {
  strings:
    $key_6c8f = { 38 e7 [2] 4c ff [2] 0b fd [2] 4c ec [2] 02 e0 [2] 0e ea [2] 19 e1 [2] 02 af [2] 3f }

  condition:
    any of them
}