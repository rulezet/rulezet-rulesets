rule TTP_XOR_MULT_DOSStub_c782 {
  strings:
    $key_c782 = { 93 ea [2] e7 f2 [2] a0 f0 [2] e7 e1 [2] a9 ed [2] a5 e7 [2] b2 ec [2] a9 a2 [2] 94 }

  condition:
    any of them
}