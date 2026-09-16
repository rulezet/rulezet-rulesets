rule TTP_XOR_MULT_DOSStub_5f97 {
  strings:
    $key_5f97 = { 0b ff [2] 7f e7 [2] 38 e5 [2] 7f f4 [2] 31 f8 [2] 3d f2 [2] 2a f9 [2] 31 b7 [2] 0c }

  condition:
    any of them
}