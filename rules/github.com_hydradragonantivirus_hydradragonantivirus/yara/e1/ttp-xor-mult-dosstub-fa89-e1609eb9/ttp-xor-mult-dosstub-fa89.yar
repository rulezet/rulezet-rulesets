rule TTP_XOR_MULT_DOSStub_fa89 {
  strings:
    $key_fa89 = { ae e1 [2] da f9 [2] 9d fb [2] da ea [2] 94 e6 [2] 98 ec [2] 8f e7 [2] 94 a9 [2] a9 }

  condition:
    any of them
}