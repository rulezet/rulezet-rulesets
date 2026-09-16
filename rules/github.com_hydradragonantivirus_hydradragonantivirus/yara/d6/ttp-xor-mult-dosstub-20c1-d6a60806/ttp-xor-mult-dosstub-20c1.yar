rule TTP_XOR_MULT_DOSStub_20c1 {
  strings:
    $key_20c1 = { 74 a9 [2] 00 b1 [2] 47 b3 [2] 00 a2 [2] 4e ae [2] 42 a4 [2] 55 af [2] 4e e1 [2] 73 }

  condition:
    any of them
}