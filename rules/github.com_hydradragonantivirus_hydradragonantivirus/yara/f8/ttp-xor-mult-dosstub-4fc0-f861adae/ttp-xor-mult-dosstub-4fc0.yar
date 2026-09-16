rule TTP_XOR_MULT_DOSStub_4fc0 {
  strings:
    $key_4fc0 = { 1b a8 [2] 6f b0 [2] 28 b2 [2] 6f a3 [2] 21 af [2] 2d a5 [2] 3a ae [2] 21 e0 [2] 1c }

  condition:
    any of them
}