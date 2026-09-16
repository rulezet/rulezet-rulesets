rule TTP_XOR_MULT_DOSStub_7a82 {
  strings:
    $key_7a82 = { 2e ea [2] 5a f2 [2] 1d f0 [2] 5a e1 [2] 14 ed [2] 18 e7 [2] 0f ec [2] 14 a2 [2] 29 }

  condition:
    any of them
}