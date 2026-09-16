rule TTP_XOR_MULT_DOSStub_b43a {
  strings:
    $key_b43a = { e0 52 [2] 94 4a [2] d3 48 [2] 94 59 [2] da 55 [2] d6 5f [2] c1 54 [2] da 1a [2] e7 }

  condition:
    any of them
}