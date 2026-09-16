rule TTP_XOR_MULT_DOSStub_0082 {
  strings:
    $key_0082 = { 54 ea [2] 20 f2 [2] 67 f0 [2] 20 e1 [2] 6e ed [2] 62 e7 [2] 75 ec [2] 6e a2 [2] 53 }

  condition:
    any of them
}