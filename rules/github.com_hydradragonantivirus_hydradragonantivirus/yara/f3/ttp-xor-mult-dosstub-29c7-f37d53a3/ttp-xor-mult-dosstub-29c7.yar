rule TTP_XOR_MULT_DOSStub_29c7 {
  strings:
    $key_29c7 = { 7d af [2] 09 b7 [2] 4e b5 [2] 09 a4 [2] 47 a8 [2] 4b a2 [2] 5c a9 [2] 47 e7 [2] 7a }

  condition:
    any of them
}