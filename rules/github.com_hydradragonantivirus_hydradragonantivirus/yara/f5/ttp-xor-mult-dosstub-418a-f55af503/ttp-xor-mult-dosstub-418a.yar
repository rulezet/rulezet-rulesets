rule TTP_XOR_MULT_DOSStub_418a {
  strings:
    $key_418a = { 15 e2 [2] 61 fa [2] 26 f8 [2] 61 e9 [2] 2f e5 [2] 23 ef [2] 34 e4 [2] 2f aa [2] 12 }

  condition:
    any of them
}