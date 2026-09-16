rule TTP_XOR_MULT_DOSStub_a690 {
  strings:
    $key_a690 = { f2 f8 [2] 86 e0 [2] c1 e2 [2] 86 f3 [2] c8 ff [2] c4 f5 [2] d3 fe [2] c8 b0 [2] f5 }

  condition:
    any of them
}