rule TTP_XOR_MULT_DOSStub_f1cc {
  strings:
    $key_f1cc = { a5 a4 [2] d1 bc [2] 96 be [2] d1 af [2] 9f a3 [2] 93 a9 [2] 84 a2 [2] 9f ec [2] a2 }

  condition:
    any of them
}