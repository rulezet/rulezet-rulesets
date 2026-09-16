rule TTP_XOR_MULT_DOSStub_808a {
  strings:
    $key_808a = { d4 e2 [2] a0 fa [2] e7 f8 [2] a0 e9 [2] ee e5 [2] e2 ef [2] f5 e4 [2] ee aa [2] d3 }

  condition:
    any of them
}