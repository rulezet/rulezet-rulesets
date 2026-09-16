rule TTP_XOR_MULT_DOSStub_248a {
  strings:
    $key_248a = { 70 e2 [2] 04 fa [2] 43 f8 [2] 04 e9 [2] 4a e5 [2] 46 ef [2] 51 e4 [2] 4a aa [2] 77 }

  condition:
    any of them
}