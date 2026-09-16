rule TTP_XOR_MULT_DOSStub_368a {
  strings:
    $key_368a = { 62 e2 [2] 16 fa [2] 51 f8 [2] 16 e9 [2] 58 e5 [2] 54 ef [2] 43 e4 [2] 58 aa [2] 65 }

  condition:
    any of them
}