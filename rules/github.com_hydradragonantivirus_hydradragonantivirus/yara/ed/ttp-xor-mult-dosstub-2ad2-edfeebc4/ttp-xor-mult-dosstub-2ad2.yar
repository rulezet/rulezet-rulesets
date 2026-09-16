rule TTP_XOR_MULT_DOSStub_2ad2 {
  strings:
    $key_2ad2 = { 7e ba [2] 0a a2 [2] 4d a0 [2] 0a b1 [2] 44 bd [2] 48 b7 [2] 5f bc [2] 44 f2 [2] 79 }

  condition:
    any of them
}