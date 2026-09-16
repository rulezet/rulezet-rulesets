rule TTP_XOR_MULT_DOSStub_1f97 {
  strings:
    $key_1f97 = { 4b ff [2] 3f e7 [2] 78 e5 [2] 3f f4 [2] 71 f8 [2] 7d f2 [2] 6a f9 [2] 71 b7 [2] 4c }

  condition:
    any of them
}