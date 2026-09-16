rule TTP_XOR_MULT_DOSStub_1cd0 {
  strings:
    $key_1cd0 = { 48 b8 [2] 3c a0 [2] 7b a2 [2] 3c b3 [2] 72 bf [2] 7e b5 [2] 69 be [2] 72 f0 [2] 4f }

  condition:
    any of them
}