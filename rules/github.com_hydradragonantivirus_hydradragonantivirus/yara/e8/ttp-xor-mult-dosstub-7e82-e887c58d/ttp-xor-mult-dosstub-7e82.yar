rule TTP_XOR_MULT_DOSStub_7e82 {
  strings:
    $key_7e82 = { 2a ea [2] 5e f2 [2] 19 f0 [2] 5e e1 [2] 10 ed [2] 1c e7 [2] 0b ec [2] 10 a2 [2] 2d }

  condition:
    any of them
}