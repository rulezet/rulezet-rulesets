rule TTP_XOR_MULT_DOSStub_b72d {
  strings:
    $key_b72d = { e3 45 [2] 97 5d [2] d0 5f [2] 97 4e [2] d9 42 [2] d5 48 [2] c2 43 [2] d9 0d [2] e4 }

  condition:
    any of them
}