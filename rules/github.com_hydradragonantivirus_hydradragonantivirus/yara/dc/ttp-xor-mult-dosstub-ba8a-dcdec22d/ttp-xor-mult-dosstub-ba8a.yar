rule TTP_XOR_MULT_DOSStub_ba8a {
  strings:
    $key_ba8a = { ee e2 [2] 9a fa [2] dd f8 [2] 9a e9 [2] d4 e5 [2] d8 ef [2] cf e4 [2] d4 aa [2] e9 }

  condition:
    any of them
}