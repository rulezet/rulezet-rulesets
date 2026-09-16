rule TTP_XOR_MULT_DOSStub_71d0 {
  strings:
    $key_71d0 = { 25 b8 [2] 51 a0 [2] 16 a2 [2] 51 b3 [2] 1f bf [2] 13 b5 [2] 04 be [2] 1f f0 [2] 22 }

  condition:
    any of them
}