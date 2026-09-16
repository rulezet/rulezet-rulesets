rule TTP_XOR_MULT_DOSStub_fa82 {
  strings:
    $key_fa82 = { ae ea [2] da f2 [2] 9d f0 [2] da e1 [2] 94 ed [2] 98 e7 [2] 8f ec [2] 94 a2 [2] a9 }

  condition:
    any of them
}