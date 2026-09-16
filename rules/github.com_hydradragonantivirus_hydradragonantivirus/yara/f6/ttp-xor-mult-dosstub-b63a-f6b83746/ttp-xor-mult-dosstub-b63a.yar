rule TTP_XOR_MULT_DOSStub_b63a {
  strings:
    $key_b63a = { e2 52 [2] 96 4a [2] d1 48 [2] 96 59 [2] d8 55 [2] d4 5f [2] c3 54 [2] d8 1a [2] e5 }

  condition:
    any of them
}