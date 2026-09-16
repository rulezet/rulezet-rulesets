rule TTP_XOR_MULT_DOSStub_0fca {
  strings:
    $key_0fca = { 5b a2 [2] 2f ba [2] 68 b8 [2] 2f a9 [2] 61 a5 [2] 6d af [2] 7a a4 [2] 61 ea [2] 5c }

  condition:
    any of them
}