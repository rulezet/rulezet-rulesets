rule TTP_XOR_MULT_DOSStub_7582 {
  strings:
    $key_7582 = { 21 ea [2] 55 f2 [2] 12 f0 [2] 55 e1 [2] 1b ed [2] 17 e7 [2] 00 ec [2] 1b a2 [2] 26 }

  condition:
    any of them
}