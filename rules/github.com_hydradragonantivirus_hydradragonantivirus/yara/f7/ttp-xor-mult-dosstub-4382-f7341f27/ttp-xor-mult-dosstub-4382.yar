rule TTP_XOR_MULT_DOSStub_4382 {
  strings:
    $key_4382 = { 17 ea [2] 63 f2 [2] 24 f0 [2] 63 e1 [2] 2d ed [2] 21 e7 [2] 36 ec [2] 2d a2 [2] 10 }

  condition:
    any of them
}