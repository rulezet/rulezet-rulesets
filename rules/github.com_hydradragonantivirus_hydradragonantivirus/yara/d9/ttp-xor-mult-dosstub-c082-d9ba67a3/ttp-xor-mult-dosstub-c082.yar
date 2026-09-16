rule TTP_XOR_MULT_DOSStub_c082 {
  strings:
    $key_c082 = { 94 ea [2] e0 f2 [2] a7 f0 [2] e0 e1 [2] ae ed [2] a2 e7 [2] b5 ec [2] ae a2 [2] 93 }

  condition:
    any of them
}