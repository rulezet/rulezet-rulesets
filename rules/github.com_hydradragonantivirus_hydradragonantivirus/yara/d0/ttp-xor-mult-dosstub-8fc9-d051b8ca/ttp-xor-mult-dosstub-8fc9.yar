rule TTP_XOR_MULT_DOSStub_8fc9 {
  strings:
    $key_8fc9 = { db a1 [2] af b9 [2] e8 bb [2] af aa [2] e1 a6 [2] ed ac [2] fa a7 [2] e1 e9 [2] dc }

  condition:
    any of them
}