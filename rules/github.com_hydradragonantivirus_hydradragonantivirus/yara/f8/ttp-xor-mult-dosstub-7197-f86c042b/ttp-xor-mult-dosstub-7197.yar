rule TTP_XOR_MULT_DOSStub_7197 {
  strings:
    $key_7197 = { 25 ff [2] 51 e7 [2] 16 e5 [2] 51 f4 [2] 1f f8 [2] 13 f2 [2] 04 f9 [2] 1f b7 [2] 22 }

  condition:
    any of them
}