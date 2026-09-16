rule TTP_XOR_MULT_DOSStub_ab8a {
  strings:
    $key_ab8a = { ff e2 [2] 8b fa [2] cc f8 [2] 8b e9 [2] c5 e5 [2] c9 ef [2] de e4 [2] c5 aa [2] f8 }

  condition:
    any of them
}