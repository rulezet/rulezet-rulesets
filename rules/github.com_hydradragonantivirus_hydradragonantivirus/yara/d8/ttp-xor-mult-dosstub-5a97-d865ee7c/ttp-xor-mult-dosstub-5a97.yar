rule TTP_XOR_MULT_DOSStub_5a97 {
  strings:
    $key_5a97 = { 0e ff [2] 7a e7 [2] 3d e5 [2] 7a f4 [2] 34 f8 [2] 38 f2 [2] 2f f9 [2] 34 b7 [2] 09 }

  condition:
    any of them
}