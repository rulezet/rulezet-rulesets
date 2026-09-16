rule TTP_XOR_MULT_DOSStub_b12d {
  strings:
    $key_b12d = { e5 45 [2] 91 5d [2] d6 5f [2] 91 4e [2] df 42 [2] d3 48 [2] c4 43 [2] df 0d [2] e2 }

  condition:
    any of them
}