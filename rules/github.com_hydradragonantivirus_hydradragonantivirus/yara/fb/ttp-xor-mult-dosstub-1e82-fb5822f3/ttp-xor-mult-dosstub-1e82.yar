rule TTP_XOR_MULT_DOSStub_1e82 {
  strings:
    $key_1e82 = { 4a ea [2] 3e f2 [2] 79 f0 [2] 3e e1 [2] 70 ed [2] 7c e7 [2] 6b ec [2] 70 a2 [2] 4d }

  condition:
    any of them
}