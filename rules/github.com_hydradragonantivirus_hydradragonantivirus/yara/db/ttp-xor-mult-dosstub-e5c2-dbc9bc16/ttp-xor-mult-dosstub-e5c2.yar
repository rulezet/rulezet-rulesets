rule TTP_XOR_MULT_DOSStub_e5c2 {
  strings:
    $key_e5c2 = { b1 aa [2] c5 b2 [2] 82 b0 [2] c5 a1 [2] 8b ad [2] 87 a7 [2] 90 ac [2] 8b e2 [2] b6 }

  condition:
    any of them
}