rule TTP_XOR_MULT_DOSStub_b2ca {
  strings:
    $key_b2ca = { e6 a2 [2] 92 ba [2] d5 b8 [2] 92 a9 [2] dc a5 [2] d0 af [2] c7 a4 [2] dc ea [2] e1 }

  condition:
    any of them
}