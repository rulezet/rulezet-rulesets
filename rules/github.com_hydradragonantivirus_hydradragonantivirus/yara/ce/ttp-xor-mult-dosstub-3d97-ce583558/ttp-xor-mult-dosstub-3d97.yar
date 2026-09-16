rule TTP_XOR_MULT_DOSStub_3d97 {
  strings:
    $key_3d97 = { 69 ff [2] 1d e7 [2] 5a e5 [2] 1d f4 [2] 53 f8 [2] 5f f2 [2] 48 f9 [2] 53 b7 [2] 6e }

  condition:
    any of them
}