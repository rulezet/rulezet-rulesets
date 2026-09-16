rule TTP_XOR_MULT_DOSStub_b08a {
  strings:
    $key_b08a = { e4 e2 [2] 90 fa [2] d7 f8 [2] 90 e9 [2] de e5 [2] d2 ef [2] c5 e4 [2] de aa [2] e3 }

  condition:
    any of them
}