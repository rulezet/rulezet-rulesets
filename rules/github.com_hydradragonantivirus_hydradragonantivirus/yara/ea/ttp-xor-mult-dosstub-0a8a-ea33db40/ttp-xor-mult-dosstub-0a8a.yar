rule TTP_XOR_MULT_DOSStub_0a8a {
  strings:
    $key_0a8a = { 5e e2 [2] 2a fa [2] 6d f8 [2] 2a e9 [2] 64 e5 [2] 68 ef [2] 7f e4 [2] 64 aa [2] 59 }

  condition:
    any of them
}