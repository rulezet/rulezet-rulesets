rule TTP_XOR_MULT_DOSStub_2ad4 {
  strings:
    $key_2ad4 = { 7e bc [2] 0a a4 [2] 4d a6 [2] 0a b7 [2] 44 bb [2] 48 b1 [2] 5f ba [2] 44 f4 [2] 79 }

  condition:
    any of them
}