rule TTP_XOR_MULT_DOSStub_6cd4 {
  strings:
    $key_6cd4 = { 38 bc [2] 4c a4 [2] 0b a6 [2] 4c b7 [2] 02 bb [2] 0e b1 [2] 19 ba [2] 02 f4 [2] 3f }

  condition:
    any of them
}