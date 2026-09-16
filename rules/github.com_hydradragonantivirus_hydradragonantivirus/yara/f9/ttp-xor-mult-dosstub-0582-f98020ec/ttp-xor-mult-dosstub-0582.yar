rule TTP_XOR_MULT_DOSStub_0582 {
  strings:
    $key_0582 = { 51 ea [2] 25 f2 [2] 62 f0 [2] 25 e1 [2] 6b ed [2] 67 e7 [2] 70 ec [2] 6b a2 [2] 56 }

  condition:
    any of them
}