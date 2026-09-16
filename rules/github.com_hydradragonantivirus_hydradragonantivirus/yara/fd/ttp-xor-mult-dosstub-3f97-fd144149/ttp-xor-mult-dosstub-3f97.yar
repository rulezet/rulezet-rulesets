rule TTP_XOR_MULT_DOSStub_3f97 {
  strings:
    $key_3f97 = { 6b ff [2] 1f e7 [2] 58 e5 [2] 1f f4 [2] 51 f8 [2] 5d f2 [2] 4a f9 [2] 51 b7 [2] 6c }

  condition:
    any of them
}