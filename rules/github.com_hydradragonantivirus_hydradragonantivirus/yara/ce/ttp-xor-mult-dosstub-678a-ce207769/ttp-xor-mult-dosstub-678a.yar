rule TTP_XOR_MULT_DOSStub_678a {
  strings:
    $key_678a = { 33 e2 [2] 47 fa [2] 00 f8 [2] 47 e9 [2] 09 e5 [2] 05 ef [2] 12 e4 [2] 09 aa [2] 34 }

  condition:
    any of them
}