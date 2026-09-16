rule TTP_XOR_MULT_DOSStub_b131 {
  strings:
    $key_b131 = { e5 59 [2] 91 41 [2] d6 43 [2] 91 52 [2] df 5e [2] d3 54 [2] c4 5f [2] df 11 [2] e2 }

  condition:
    any of them
}