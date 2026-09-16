rule TTP_XOR_MULT_DOSStub_5982 {
  strings:
    $key_5982 = { 0d ea [2] 79 f2 [2] 3e f0 [2] 79 e1 [2] 37 ed [2] 3b e7 [2] 2c ec [2] 37 a2 [2] 0a }

  condition:
    any of them
}