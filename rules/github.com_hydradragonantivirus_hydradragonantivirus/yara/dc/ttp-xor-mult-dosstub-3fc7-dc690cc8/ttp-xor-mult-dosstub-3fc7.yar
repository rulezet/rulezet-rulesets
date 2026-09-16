rule TTP_XOR_MULT_DOSStub_3fc7 {
  strings:
    $key_3fc7 = { 6b af [2] 1f b7 [2] 58 b5 [2] 1f a4 [2] 51 a8 [2] 5d a2 [2] 4a a9 [2] 51 e7 [2] 6c }

  condition:
    any of them
}