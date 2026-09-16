rule TTP_XOR_MULT_DOSStub_b101 {
  strings:
    $key_b101 = { e5 69 [2] 91 71 [2] d6 73 [2] 91 62 [2] df 6e [2] d3 64 [2] c4 6f [2] df 21 [2] e2 }

  condition:
    any of them
}