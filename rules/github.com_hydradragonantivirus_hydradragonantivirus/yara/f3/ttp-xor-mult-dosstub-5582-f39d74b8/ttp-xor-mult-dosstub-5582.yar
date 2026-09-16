rule TTP_XOR_MULT_DOSStub_5582 {
  strings:
    $key_5582 = { 01 ea [2] 75 f2 [2] 32 f0 [2] 75 e1 [2] 3b ed [2] 37 e7 [2] 20 ec [2] 3b a2 [2] 06 }

  condition:
    any of them
}