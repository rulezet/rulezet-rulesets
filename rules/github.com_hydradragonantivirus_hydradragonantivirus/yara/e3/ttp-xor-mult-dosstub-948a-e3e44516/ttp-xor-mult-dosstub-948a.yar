rule TTP_XOR_MULT_DOSStub_948a {
  strings:
    $key_948a = { c0 e2 [2] b4 fa [2] f3 f8 [2] b4 e9 [2] fa e5 [2] f6 ef [2] e1 e4 [2] fa aa [2] c7 }

  condition:
    any of them
}