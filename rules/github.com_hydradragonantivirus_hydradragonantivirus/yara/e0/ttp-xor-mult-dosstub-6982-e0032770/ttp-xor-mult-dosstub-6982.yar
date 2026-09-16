rule TTP_XOR_MULT_DOSStub_6982 {
  strings:
    $key_6982 = { 3d ea [2] 49 f2 [2] 0e f0 [2] 49 e1 [2] 07 ed [2] 0b e7 [2] 1c ec [2] 07 a2 [2] 3a }

  condition:
    any of them
}