rule TTP_XOR_MULT_DOSStub_b29a {
  strings:
    $key_b29a = { e6 f2 [2] 92 ea [2] d5 e8 [2] 92 f9 [2] dc f5 [2] d0 ff [2] c7 f4 [2] dc ba [2] e1 }

  condition:
    any of them
}