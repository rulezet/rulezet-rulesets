rule TTP_XOR_MULT_DOSStub_4b8a {
  strings:
    $key_4b8a = { 1f e2 [2] 6b fa [2] 2c f8 [2] 6b e9 [2] 25 e5 [2] 29 ef [2] 3e e4 [2] 25 aa [2] 18 }

  condition:
    any of them
}