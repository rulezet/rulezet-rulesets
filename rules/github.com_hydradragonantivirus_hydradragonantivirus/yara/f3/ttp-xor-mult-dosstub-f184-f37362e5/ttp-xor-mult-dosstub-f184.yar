rule TTP_XOR_MULT_DOSStub_f184 {
  strings:
    $key_f184 = { a5 ec [2] d1 f4 [2] 96 f6 [2] d1 e7 [2] 9f eb [2] 93 e1 [2] 84 ea [2] 9f a4 [2] a2 }

  condition:
    any of them
}