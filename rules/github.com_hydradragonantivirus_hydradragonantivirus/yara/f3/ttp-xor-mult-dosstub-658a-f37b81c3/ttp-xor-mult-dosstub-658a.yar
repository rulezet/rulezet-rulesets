rule TTP_XOR_MULT_DOSStub_658a {
  strings:
    $key_658a = { 31 e2 [2] 45 fa [2] 02 f8 [2] 45 e9 [2] 0b e5 [2] 07 ef [2] 10 e4 [2] 0b aa [2] 36 }

  condition:
    any of them
}