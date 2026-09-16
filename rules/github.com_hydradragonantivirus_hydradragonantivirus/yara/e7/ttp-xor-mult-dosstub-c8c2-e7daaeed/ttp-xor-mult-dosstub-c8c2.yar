rule TTP_XOR_MULT_DOSStub_c8c2 {
  strings:
    $key_c8c2 = { 9c aa [2] e8 b2 [2] af b0 [2] e8 a1 [2] a6 ad [2] aa a7 [2] bd ac [2] a6 e2 [2] 9b }

  condition:
    any of them
}