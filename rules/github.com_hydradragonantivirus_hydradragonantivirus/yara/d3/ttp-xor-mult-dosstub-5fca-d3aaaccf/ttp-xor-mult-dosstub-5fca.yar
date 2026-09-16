rule TTP_XOR_MULT_DOSStub_5fca {
  strings:
    $key_5fca = { 0b a2 [2] 7f ba [2] 38 b8 [2] 7f a9 [2] 31 a5 [2] 3d af [2] 2a a4 [2] 31 ea [2] 0c }

  condition:
    any of them
}