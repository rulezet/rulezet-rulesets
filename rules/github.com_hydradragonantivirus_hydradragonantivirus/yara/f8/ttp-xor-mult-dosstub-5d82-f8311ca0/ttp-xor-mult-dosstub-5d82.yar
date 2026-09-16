rule TTP_XOR_MULT_DOSStub_5d82 {
  strings:
    $key_5d82 = { 09 ea [2] 7d f2 [2] 3a f0 [2] 7d e1 [2] 33 ed [2] 3f e7 [2] 28 ec [2] 33 a2 [2] 0e }

  condition:
    any of them
}