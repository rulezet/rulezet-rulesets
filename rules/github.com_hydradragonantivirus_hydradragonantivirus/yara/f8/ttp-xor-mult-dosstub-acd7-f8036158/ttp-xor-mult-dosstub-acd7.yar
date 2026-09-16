rule TTP_XOR_MULT_DOSStub_acd7 {
  strings:
    $key_acd7 = { f8 bf [2] 8c a7 [2] cb a5 [2] 8c b4 [2] c2 b8 [2] ce b2 [2] d9 b9 [2] c2 f7 [2] ff }

  condition:
    any of them
}