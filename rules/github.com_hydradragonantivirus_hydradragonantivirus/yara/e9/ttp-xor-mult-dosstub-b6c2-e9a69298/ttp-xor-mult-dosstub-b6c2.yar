rule TTP_XOR_MULT_DOSStub_b6c2 {
  strings:
    $key_b6c2 = { e2 aa [2] 96 b2 [2] d1 b0 [2] 96 a1 [2] d8 ad [2] d4 a7 [2] c3 ac [2] d8 e2 [2] e5 }

  condition:
    any of them
}