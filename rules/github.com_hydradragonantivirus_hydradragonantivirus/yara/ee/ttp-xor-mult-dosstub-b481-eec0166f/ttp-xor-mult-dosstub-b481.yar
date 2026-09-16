rule TTP_XOR_MULT_DOSStub_b481 {
  strings:
    $key_b481 = { e0 e9 [2] 94 f1 [2] d3 f3 [2] 94 e2 [2] da ee [2] d6 e4 [2] c1 ef [2] da a1 [2] e7 }

  condition:
    any of them
}