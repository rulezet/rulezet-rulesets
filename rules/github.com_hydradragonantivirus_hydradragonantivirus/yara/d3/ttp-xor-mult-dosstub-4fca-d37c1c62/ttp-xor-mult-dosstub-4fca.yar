rule TTP_XOR_MULT_DOSStub_4fca {
  strings:
    $key_4fca = { 1b a2 [2] 6f ba [2] 28 b8 [2] 6f a9 [2] 21 a5 [2] 2d af [2] 3a a4 [2] 21 ea [2] 1c }

  condition:
    any of them
}