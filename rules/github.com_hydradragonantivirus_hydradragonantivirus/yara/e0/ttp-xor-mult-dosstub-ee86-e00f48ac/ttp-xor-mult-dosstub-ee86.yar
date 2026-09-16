rule TTP_XOR_MULT_DOSStub_ee86 {
  strings:
    $key_ee86 = { ba ee [2] ce f6 [2] 89 f4 [2] ce e5 [2] 80 e9 [2] 8c e3 [2] 9b e8 [2] 80 a6 [2] bd }

  condition:
    any of them
}