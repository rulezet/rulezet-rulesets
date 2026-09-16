rule TTP_XOR_MULT_DOSStub_a791 {
  strings:
    $key_a791 = { f3 f9 [2] 87 e1 [2] c0 e3 [2] 87 f2 [2] c9 fe [2] c5 f4 [2] d2 ff [2] c9 b1 [2] f4 }

  condition:
    any of them
}