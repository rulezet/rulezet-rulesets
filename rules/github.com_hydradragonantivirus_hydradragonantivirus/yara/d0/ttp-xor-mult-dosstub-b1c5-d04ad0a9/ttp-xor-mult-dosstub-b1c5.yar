rule TTP_XOR_MULT_DOSStub_b1c5 {
  strings:
    $key_b1c5 = { e5 ad [2] 91 b5 [2] d6 b7 [2] 91 a6 [2] df aa [2] d3 a0 [2] c4 ab [2] df e5 [2] e2 }

  condition:
    any of them
}