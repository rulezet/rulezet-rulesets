rule TTP_XOR_MULT_DOSStub_c5c2 {
  strings:
    $key_c5c2 = { 91 aa [2] e5 b2 [2] a2 b0 [2] e5 a1 [2] ab ad [2] a7 a7 [2] b0 ac [2] ab e2 [2] 96 }

  condition:
    any of them
}