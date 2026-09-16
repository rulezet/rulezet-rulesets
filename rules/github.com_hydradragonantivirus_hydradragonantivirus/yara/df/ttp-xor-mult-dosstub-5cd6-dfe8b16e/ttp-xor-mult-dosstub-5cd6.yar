rule TTP_XOR_MULT_DOSStub_5cd6 {
  strings:
    $key_5cd6 = { 08 be [2] 7c a6 [2] 3b a4 [2] 7c b5 [2] 32 b9 [2] 3e b3 [2] 29 b8 [2] 32 f6 [2] 0f }

  condition:
    any of them
}