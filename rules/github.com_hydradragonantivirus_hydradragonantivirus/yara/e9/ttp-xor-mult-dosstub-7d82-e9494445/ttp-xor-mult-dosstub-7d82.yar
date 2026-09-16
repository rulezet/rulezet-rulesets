rule TTP_XOR_MULT_DOSStub_7d82 {
  strings:
    $key_7d82 = { 29 ea [2] 5d f2 [2] 1a f0 [2] 5d e1 [2] 13 ed [2] 1f e7 [2] 08 ec [2] 13 a2 [2] 2e }

  condition:
    any of them
}