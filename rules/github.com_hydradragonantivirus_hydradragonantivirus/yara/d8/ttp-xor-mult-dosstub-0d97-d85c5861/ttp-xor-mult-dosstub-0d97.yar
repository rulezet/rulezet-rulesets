rule TTP_XOR_MULT_DOSStub_0d97 {
  strings:
    $key_0d97 = { 59 ff [2] 2d e7 [2] 6a e5 [2] 2d f4 [2] 63 f8 [2] 6f f2 [2] 78 f9 [2] 63 b7 [2] 5e }

  condition:
    any of them
}