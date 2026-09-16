rule TTP_XOR_MULT_DOSStub_5a8a {
  strings:
    $key_5a8a = { 0e e2 [2] 7a fa [2] 3d f8 [2] 7a e9 [2] 34 e5 [2] 38 ef [2] 2f e4 [2] 34 aa [2] 09 }

  condition:
    any of them
}