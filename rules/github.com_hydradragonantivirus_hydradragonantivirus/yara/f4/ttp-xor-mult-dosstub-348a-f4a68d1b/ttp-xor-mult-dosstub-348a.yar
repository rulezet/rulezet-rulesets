rule TTP_XOR_MULT_DOSStub_348a {
  strings:
    $key_348a = { 60 e2 [2] 14 fa [2] 53 f8 [2] 14 e9 [2] 5a e5 [2] 56 ef [2] 41 e4 [2] 5a aa [2] 67 }

  condition:
    any of them
}