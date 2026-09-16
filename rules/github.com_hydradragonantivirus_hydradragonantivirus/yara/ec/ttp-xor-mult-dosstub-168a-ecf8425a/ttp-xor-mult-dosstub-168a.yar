rule TTP_XOR_MULT_DOSStub_168a {
  strings:
    $key_168a = { 42 e2 [2] 36 fa [2] 71 f8 [2] 36 e9 [2] 78 e5 [2] 74 ef [2] 63 e4 [2] 78 aa [2] 45 }

  condition:
    any of them
}