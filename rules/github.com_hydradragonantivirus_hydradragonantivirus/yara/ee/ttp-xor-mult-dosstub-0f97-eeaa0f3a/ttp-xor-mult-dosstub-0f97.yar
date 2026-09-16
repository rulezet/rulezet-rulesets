rule TTP_XOR_MULT_DOSStub_0f97 {
  strings:
    $key_0f97 = { 5b ff [2] 2f e7 [2] 68 e5 [2] 2f f4 [2] 61 f8 [2] 6d f2 [2] 7a f9 [2] 61 b7 [2] 5c }

  condition:
    any of them
}