rule TTP_XOR_MULT_DOSStub_70c1 {
  strings:
    $key_70c1 = { 24 a9 [2] 50 b1 [2] 17 b3 [2] 50 a2 [2] 1e ae [2] 12 a4 [2] 05 af [2] 1e e1 [2] 23 }

  condition:
    any of them
}