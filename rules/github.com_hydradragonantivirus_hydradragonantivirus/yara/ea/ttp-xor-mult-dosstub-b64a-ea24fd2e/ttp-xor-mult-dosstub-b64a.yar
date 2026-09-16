rule TTP_XOR_MULT_DOSStub_b64a {
  strings:
    $key_b64a = { e2 22 [2] 96 3a [2] d1 38 [2] 96 29 [2] d8 25 [2] d4 2f [2] c3 24 [2] d8 6a [2] e5 }

  condition:
    any of them
}