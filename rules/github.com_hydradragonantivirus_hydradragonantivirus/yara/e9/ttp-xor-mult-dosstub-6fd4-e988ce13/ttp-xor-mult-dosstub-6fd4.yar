rule TTP_XOR_MULT_DOSStub_6fd4 {
  strings:
    $key_6fd4 = { 3b bc [2] 4f a4 [2] 08 a6 [2] 4f b7 [2] 01 bb [2] 0d b1 [2] 1a ba [2] 01 f4 [2] 3c }

  condition:
    any of them
}