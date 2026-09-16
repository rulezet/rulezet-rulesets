rule TTP_XOR_MULT_DOSStub_b150 {
  strings:
    $key_b150 = { e5 38 [2] 91 20 [2] d6 22 [2] 91 33 [2] df 3f [2] d3 35 [2] c4 3e [2] df 70 [2] e2 }

  condition:
    any of them
}