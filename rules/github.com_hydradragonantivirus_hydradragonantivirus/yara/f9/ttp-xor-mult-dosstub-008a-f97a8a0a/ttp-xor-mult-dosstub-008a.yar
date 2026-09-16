rule TTP_XOR_MULT_DOSStub_008a {
  strings:
    $key_008a = { 54 e2 [2] 20 fa [2] 67 f8 [2] 20 e9 [2] 6e e5 [2] 62 ef [2] 75 e4 [2] 6e aa [2] 53 }

  condition:
    any of them
}