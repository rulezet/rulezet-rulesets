rule TTP_XOR_MULT_DOSStub_b1c7 {
  strings:
    $key_b1c7 = { e5 af [2] 91 b7 [2] d6 b5 [2] 91 a4 [2] df a8 [2] d3 a2 [2] c4 a9 [2] df e7 [2] e2 }

  condition:
    any of them
}