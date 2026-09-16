rule TTP_XOR_MULT_DOSStub_a9c2 {
  strings:
    $key_a9c2 = { fd aa [2] 89 b2 [2] ce b0 [2] 89 a1 [2] c7 ad [2] cb a7 [2] dc ac [2] c7 e2 [2] fa }

  condition:
    any of them
}