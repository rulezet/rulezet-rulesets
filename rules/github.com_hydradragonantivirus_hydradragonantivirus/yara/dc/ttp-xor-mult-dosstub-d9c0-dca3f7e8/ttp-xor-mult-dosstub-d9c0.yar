rule TTP_XOR_MULT_DOSStub_d9c0 {
  strings:
    $key_d9c0 = { 8d a8 [2] f9 b0 [2] be b2 [2] f9 a3 [2] b7 af [2] bb a5 [2] ac ae [2] b7 e0 [2] 8a }

  condition:
    any of them
}