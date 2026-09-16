rule TTP_XOR_MULT_DOSStub_b1e0 {
  strings:
    $key_b1e0 = { e5 88 [2] 91 90 [2] d6 92 [2] 91 83 [2] df 8f [2] d3 85 [2] c4 8e [2] df c0 [2] e2 }

  condition:
    any of them
}