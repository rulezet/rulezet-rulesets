rule TTP_XOR_MULT_DOSStub_d08a {
  strings:
    $key_d08a = { 84 e2 [2] f0 fa [2] b7 f8 [2] f0 e9 [2] be e5 [2] b2 ef [2] a5 e4 [2] be aa [2] 83 }

  condition:
    any of them
}