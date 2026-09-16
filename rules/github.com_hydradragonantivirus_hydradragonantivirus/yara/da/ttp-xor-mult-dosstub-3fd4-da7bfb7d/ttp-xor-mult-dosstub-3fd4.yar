rule TTP_XOR_MULT_DOSStub_3fd4 {
  strings:
    $key_3fd4 = { 6b bc [2] 1f a4 [2] 58 a6 [2] 1f b7 [2] 51 bb [2] 5d b1 [2] 4a ba [2] 51 f4 [2] 6c }

  condition:
    any of them
}