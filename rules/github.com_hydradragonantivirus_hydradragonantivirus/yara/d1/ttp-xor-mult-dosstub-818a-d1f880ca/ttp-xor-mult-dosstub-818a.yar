rule TTP_XOR_MULT_DOSStub_818a {
  strings:
    $key_818a = { d5 e2 [2] a1 fa [2] e6 f8 [2] a1 e9 [2] ef e5 [2] e3 ef [2] f4 e4 [2] ef aa [2] d2 }

  condition:
    any of them
}