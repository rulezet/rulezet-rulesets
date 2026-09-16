rule TTP_XOR_MULT_DOSStub_028a {
  strings:
    $key_028a = { 56 e2 [2] 22 fa [2] 65 f8 [2] 22 e9 [2] 6c e5 [2] 60 ef [2] 77 e4 [2] 6c aa [2] 51 }

  condition:
    any of them
}