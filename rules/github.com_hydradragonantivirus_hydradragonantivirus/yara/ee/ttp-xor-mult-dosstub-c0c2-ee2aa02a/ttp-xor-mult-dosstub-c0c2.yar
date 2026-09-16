rule TTP_XOR_MULT_DOSStub_c0c2 {
  strings:
    $key_c0c2 = { 94 aa [2] e0 b2 [2] a7 b0 [2] e0 a1 [2] ae ad [2] a2 a7 [2] b5 ac [2] ae e2 [2] 93 }

  condition:
    any of them
}