rule TTP_XOR_MULT_DOSStub_b1e7 {
  strings:
    $key_b1e7 = { e5 8f [2] 91 97 [2] d6 95 [2] 91 84 [2] df 88 [2] d3 82 [2] c4 89 [2] df c7 [2] e2 }

  condition:
    any of them
}