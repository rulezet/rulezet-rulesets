rule TTP_XOR_MULT_DOSStub_a790 {
  strings:
    $key_a790 = { f3 f8 [2] 87 e0 [2] c0 e2 [2] 87 f3 [2] c9 ff [2] c5 f5 [2] d2 fe [2] c9 b0 [2] f4 }

  condition:
    any of them
}