rule TTP_XOR_MULT_DOSStub_2c97 {
  strings:
    $key_2c97 = { 78 ff [2] 0c e7 [2] 4b e5 [2] 0c f4 [2] 42 f8 [2] 4e f2 [2] 59 f9 [2] 42 b7 [2] 7f }

  condition:
    any of them
}