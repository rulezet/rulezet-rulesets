rule TTP_XOR_MULT_DOSStub_b1c2 {
  strings:
    $key_b1c2 = { e5 aa [2] 91 b2 [2] d6 b0 [2] 91 a1 [2] df ad [2] d3 a7 [2] c4 ac [2] df e2 [2] e2 }

  condition:
    any of them
}