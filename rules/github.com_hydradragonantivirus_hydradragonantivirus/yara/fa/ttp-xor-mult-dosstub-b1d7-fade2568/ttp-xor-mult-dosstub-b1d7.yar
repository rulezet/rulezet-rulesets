rule TTP_XOR_MULT_DOSStub_b1d7 {
  strings:
    $key_b1d7 = { e5 bf [2] 91 a7 [2] d6 a5 [2] 91 b4 [2] df b8 [2] d3 b2 [2] c4 b9 [2] df f7 [2] e2 }

  condition:
    any of them
}