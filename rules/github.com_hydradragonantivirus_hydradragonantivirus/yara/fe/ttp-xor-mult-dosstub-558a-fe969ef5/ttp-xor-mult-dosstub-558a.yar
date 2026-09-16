rule TTP_XOR_MULT_DOSStub_558a {
  strings:
    $key_558a = { 01 e2 [2] 75 fa [2] 32 f8 [2] 75 e9 [2] 3b e5 [2] 37 ef [2] 20 e4 [2] 3b aa [2] 06 }

  condition:
    any of them
}