rule TTP_XOR_MULT_DOSStub_4fd4 {
  strings:
    $key_4fd4 = { 1b bc [2] 6f a4 [2] 28 a6 [2] 6f b7 [2] 21 bb [2] 2d b1 [2] 3a ba [2] 21 f4 [2] 1c }

  condition:
    any of them
}