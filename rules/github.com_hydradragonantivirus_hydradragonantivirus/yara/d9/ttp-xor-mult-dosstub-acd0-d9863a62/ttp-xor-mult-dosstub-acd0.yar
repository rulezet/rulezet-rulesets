rule TTP_XOR_MULT_DOSStub_acd0 {
  strings:
    $key_acd0 = { f8 b8 [2] 8c a0 [2] cb a2 [2] 8c b3 [2] c2 bf [2] ce b5 [2] d9 be [2] c2 f0 [2] ff }

  condition:
    any of them
}