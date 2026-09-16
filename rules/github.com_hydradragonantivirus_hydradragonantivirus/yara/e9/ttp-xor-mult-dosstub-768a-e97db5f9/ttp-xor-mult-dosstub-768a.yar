rule TTP_XOR_MULT_DOSStub_768a {
  strings:
    $key_768a = { 22 e2 [2] 56 fa [2] 11 f8 [2] 56 e9 [2] 18 e5 [2] 14 ef [2] 03 e4 [2] 18 aa [2] 25 }

  condition:
    any of them
}