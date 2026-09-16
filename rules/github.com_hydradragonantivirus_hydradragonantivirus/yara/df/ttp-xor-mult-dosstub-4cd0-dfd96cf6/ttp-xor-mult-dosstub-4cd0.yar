rule TTP_XOR_MULT_DOSStub_4cd0 {
  strings:
    $key_4cd0 = { 18 b8 [2] 6c a0 [2] 2b a2 [2] 6c b3 [2] 22 bf [2] 2e b5 [2] 39 be [2] 22 f0 [2] 1f }

  condition:
    any of them
}