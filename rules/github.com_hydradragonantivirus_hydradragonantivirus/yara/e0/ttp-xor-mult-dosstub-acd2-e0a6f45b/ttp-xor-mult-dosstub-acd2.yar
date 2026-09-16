rule TTP_XOR_MULT_DOSStub_acd2 {
  strings:
    $key_acd2 = { f8 ba [2] 8c a2 [2] cb a0 [2] 8c b1 [2] c2 bd [2] ce b7 [2] d9 bc [2] c2 f2 [2] ff }

  condition:
    any of them
}