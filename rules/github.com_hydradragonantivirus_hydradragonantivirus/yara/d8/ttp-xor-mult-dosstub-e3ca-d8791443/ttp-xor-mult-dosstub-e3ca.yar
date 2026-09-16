rule TTP_XOR_MULT_DOSStub_e3ca {
  strings:
    $key_e3ca = { b7 a2 [2] c3 ba [2] 84 b8 [2] c3 a9 [2] 8d a5 [2] 81 af [2] 96 a4 [2] 8d ea [2] b0 }

  condition:
    any of them
}