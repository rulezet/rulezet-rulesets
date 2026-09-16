rule TTP_XOR_MULT_DOSStub_6cd2 {
  strings:
    $key_6cd2 = { 38 ba [2] 4c a2 [2] 0b a0 [2] 4c b1 [2] 02 bd [2] 0e b7 [2] 19 bc [2] 02 f2 [2] 3f }

  condition:
    any of them
}