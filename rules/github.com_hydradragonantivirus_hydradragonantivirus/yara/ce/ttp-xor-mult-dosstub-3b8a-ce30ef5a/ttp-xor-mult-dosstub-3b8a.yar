rule TTP_XOR_MULT_DOSStub_3b8a {
  strings:
    $key_3b8a = { 6f e2 [2] 1b fa [2] 5c f8 [2] 1b e9 [2] 55 e5 [2] 59 ef [2] 4e e4 [2] 55 aa [2] 68 }

  condition:
    any of them
}