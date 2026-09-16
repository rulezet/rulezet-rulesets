rule TTP_XOR_MULT_DOSStub_00c1 {
  strings:
    $key_00c1 = { 54 a9 [2] 20 b1 [2] 67 b3 [2] 20 a2 [2] 6e ae [2] 62 a4 [2] 75 af [2] 6e e1 [2] 53 }

  condition:
    any of them
}