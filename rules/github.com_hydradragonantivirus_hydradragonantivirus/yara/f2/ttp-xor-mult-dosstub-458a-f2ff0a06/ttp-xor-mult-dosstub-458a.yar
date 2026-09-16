rule TTP_XOR_MULT_DOSStub_458a {
  strings:
    $key_458a = { 11 e2 [2] 65 fa [2] 22 f8 [2] 65 e9 [2] 2b e5 [2] 27 ef [2] 30 e4 [2] 2b aa [2] 16 }

  condition:
    any of them
}