rule TTP_XOR_MULT_DOSStub_b78a {
  strings:
    $key_b78a = { e3 e2 [2] 97 fa [2] d0 f8 [2] 97 e9 [2] d9 e5 [2] d5 ef [2] c2 e4 [2] d9 aa [2] e4 }

  condition:
    any of them
}