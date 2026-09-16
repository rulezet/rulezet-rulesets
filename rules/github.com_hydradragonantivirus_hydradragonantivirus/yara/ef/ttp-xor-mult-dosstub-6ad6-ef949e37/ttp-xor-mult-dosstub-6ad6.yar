rule TTP_XOR_MULT_DOSStub_6ad6 {
  strings:
    $key_6ad6 = { 3e be [2] 4a a6 [2] 0d a4 [2] 4a b5 [2] 04 b9 [2] 08 b3 [2] 1f b8 [2] 04 f6 [2] 39 }

  condition:
    any of them
}