rule TTP_XOR_MULT_DOSStub_3e82 {
  strings:
    $key_3e82 = { 6a ea [2] 1e f2 [2] 59 f0 [2] 1e e1 [2] 50 ed [2] 5c e7 [2] 4b ec [2] 50 a2 [2] 6d }

  condition:
    any of them
}