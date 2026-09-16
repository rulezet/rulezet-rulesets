rule TTP_XOR_MULT_DOSStub_b1c0 {
  strings:
    $key_b1c0 = { e5 a8 [2] 91 b0 [2] d6 b2 [2] 91 a3 [2] df af [2] d3 a5 [2] c4 ae [2] df e0 [2] e2 }

  condition:
    any of them
}