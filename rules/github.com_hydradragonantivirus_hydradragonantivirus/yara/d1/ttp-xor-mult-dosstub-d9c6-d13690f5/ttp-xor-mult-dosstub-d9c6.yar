rule TTP_XOR_MULT_DOSStub_d9c6 {
  strings:
    $key_d9c6 = { 8d ae [2] f9 b6 [2] be b4 [2] f9 a5 [2] b7 a9 [2] bb a3 [2] ac a8 [2] b7 e6 [2] 8a }

  condition:
    any of them
}