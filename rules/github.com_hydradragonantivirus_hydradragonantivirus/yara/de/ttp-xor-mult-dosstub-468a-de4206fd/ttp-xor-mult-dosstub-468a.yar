rule TTP_XOR_MULT_DOSStub_468a {
  strings:
    $key_468a = { 12 e2 [2] 66 fa [2] 21 f8 [2] 66 e9 [2] 28 e5 [2] 24 ef [2] 33 e4 [2] 28 aa [2] 15 }

  condition:
    any of them
}