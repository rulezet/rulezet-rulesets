rule TTP_XOR_MULT_DOSStub_4cd1 {
  strings:
    $key_4cd1 = { 18 b9 [2] 6c a1 [2] 2b a3 [2] 6c b2 [2] 22 be [2] 2e b4 [2] 39 bf [2] 22 f1 [2] 1f }

  condition:
    any of them
}