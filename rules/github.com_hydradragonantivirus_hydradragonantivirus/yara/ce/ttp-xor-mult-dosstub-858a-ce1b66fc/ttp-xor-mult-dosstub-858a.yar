rule TTP_XOR_MULT_DOSStub_858a {
  strings:
    $key_858a = { d1 e2 [2] a5 fa [2] e2 f8 [2] a5 e9 [2] eb e5 [2] e7 ef [2] f0 e4 [2] eb aa [2] d6 }

  condition:
    any of them
}