rule TTP_XOR_MULT_DOSStub_b71a {
  strings:
    $key_b71a = { e3 72 [2] 97 6a [2] d0 68 [2] 97 79 [2] d9 75 [2] d5 7f [2] c2 74 [2] d9 3a [2] e4 }

  condition:
    any of them
}