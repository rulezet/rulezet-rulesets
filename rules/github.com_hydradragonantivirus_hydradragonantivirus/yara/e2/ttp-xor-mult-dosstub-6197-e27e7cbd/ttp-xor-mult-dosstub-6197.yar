rule TTP_XOR_MULT_DOSStub_6197 {
  strings:
    $key_6197 = { 35 ff [2] 41 e7 [2] 06 e5 [2] 41 f4 [2] 0f f8 [2] 03 f2 [2] 14 f9 [2] 0f b7 [2] 32 }

  condition:
    any of them
}