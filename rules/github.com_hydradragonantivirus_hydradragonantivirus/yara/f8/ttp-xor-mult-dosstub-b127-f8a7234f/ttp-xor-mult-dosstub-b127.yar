rule TTP_XOR_MULT_DOSStub_b127 {
  strings:
    $key_b127 = { e5 4f [2] 91 57 [2] d6 55 [2] 91 44 [2] df 48 [2] d3 42 [2] c4 49 [2] df 07 [2] e2 }

  condition:
    any of them
}