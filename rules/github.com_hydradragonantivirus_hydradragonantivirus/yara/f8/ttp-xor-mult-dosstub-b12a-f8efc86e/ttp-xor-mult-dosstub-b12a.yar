rule TTP_XOR_MULT_DOSStub_b12a {
  strings:
    $key_b12a = { e5 42 [2] 91 5a [2] d6 58 [2] 91 49 [2] df 45 [2] d3 4f [2] c4 44 [2] df 0a [2] e2 }

  condition:
    any of them
}