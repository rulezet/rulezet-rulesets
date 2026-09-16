rule TTP_XOR_MULT_DOSStub_0b8a {
  strings:
    $key_0b8a = { 5f e2 [2] 2b fa [2] 6c f8 [2] 2b e9 [2] 65 e5 [2] 69 ef [2] 7e e4 [2] 65 aa [2] 58 }

  condition:
    any of them
}