rule TTP_XOR_MULT_DOSStub_b63d {
  strings:
    $key_b63d = { e2 55 [2] 96 4d [2] d1 4f [2] 96 5e [2] d8 52 [2] d4 58 [2] c3 53 [2] d8 1d [2] e5 }

  condition:
    any of them
}