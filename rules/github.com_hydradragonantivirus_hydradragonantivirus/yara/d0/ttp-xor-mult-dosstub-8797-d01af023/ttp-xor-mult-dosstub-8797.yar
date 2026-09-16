rule TTP_XOR_MULT_DOSStub_8797 {
  strings:
    $key_8797 = { d3 ff [2] a7 e7 [2] e0 e5 [2] a7 f4 [2] e9 f8 [2] e5 f2 [2] f2 f9 [2] e9 b7 [2] d4 }

  condition:
    any of them
}