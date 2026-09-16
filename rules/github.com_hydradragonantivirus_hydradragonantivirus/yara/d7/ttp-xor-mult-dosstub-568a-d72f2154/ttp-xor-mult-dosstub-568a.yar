rule TTP_XOR_MULT_DOSStub_568a {
  strings:
    $key_568a = { 02 e2 [2] 76 fa [2] 31 f8 [2] 76 e9 [2] 38 e5 [2] 34 ef [2] 23 e4 [2] 38 aa [2] 05 }

  condition:
    any of them
}