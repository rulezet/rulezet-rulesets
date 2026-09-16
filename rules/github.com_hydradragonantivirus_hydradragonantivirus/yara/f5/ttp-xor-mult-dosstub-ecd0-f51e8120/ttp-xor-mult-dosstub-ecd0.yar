rule TTP_XOR_MULT_DOSStub_ecd0 {
  strings:
    $key_ecd0 = { b8 b8 [2] cc a0 [2] 8b a2 [2] cc b3 [2] 82 bf [2] 8e b5 [2] 99 be [2] 82 f0 [2] bf }

  condition:
    any of them
}