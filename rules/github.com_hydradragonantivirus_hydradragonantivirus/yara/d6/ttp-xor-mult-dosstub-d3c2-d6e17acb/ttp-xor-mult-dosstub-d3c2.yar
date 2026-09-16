rule TTP_XOR_MULT_DOSStub_d3c2 {
  strings:
    $key_d3c2 = { 87 aa [2] f3 b2 [2] b4 b0 [2] f3 a1 [2] bd ad [2] b1 a7 [2] a6 ac [2] bd e2 [2] 80 }

  condition:
    any of them
}