rule TTP_XOR_MULT_DOSStub_aa8a {
  strings:
    $key_aa8a = { fe e2 [2] 8a fa [2] cd f8 [2] 8a e9 [2] c4 e5 [2] c8 ef [2] df e4 [2] c4 aa [2] f9 }

  condition:
    any of them
}