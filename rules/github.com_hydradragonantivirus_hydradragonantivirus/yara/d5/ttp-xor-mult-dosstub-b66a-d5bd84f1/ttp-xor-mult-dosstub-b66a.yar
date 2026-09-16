rule TTP_XOR_MULT_DOSStub_b66a {
  strings:
    $key_b66a = { e2 02 [2] 96 1a [2] d1 18 [2] 96 09 [2] d8 05 [2] d4 0f [2] c3 04 [2] d8 4a [2] e5 }

  condition:
    any of them
}