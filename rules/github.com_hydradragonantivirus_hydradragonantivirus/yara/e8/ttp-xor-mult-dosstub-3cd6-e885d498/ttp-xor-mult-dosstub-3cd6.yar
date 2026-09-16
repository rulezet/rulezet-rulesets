rule TTP_XOR_MULT_DOSStub_3cd6 {
  strings:
    $key_3cd6 = { 68 be [2] 1c a6 [2] 5b a4 [2] 1c b5 [2] 52 b9 [2] 5e b3 [2] 49 b8 [2] 52 f6 [2] 6f }

  condition:
    any of them
}