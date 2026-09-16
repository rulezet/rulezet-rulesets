rule TTP_XOR_MULT_DOSStub_6cd9 {
  strings:
    $key_6cd9 = { 38 b1 [2] 4c a9 [2] 0b ab [2] 4c ba [2] 02 b6 [2] 0e bc [2] 19 b7 [2] 02 f9 [2] 3f }

  condition:
    any of them
}