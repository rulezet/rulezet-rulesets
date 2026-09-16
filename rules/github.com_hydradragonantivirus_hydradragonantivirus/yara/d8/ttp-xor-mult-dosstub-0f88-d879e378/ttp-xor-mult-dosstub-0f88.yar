rule TTP_XOR_MULT_DOSStub_0f88 {
  strings:
    $key_0f88 = { 5b e0 [2] 2f f8 [2] 68 fa [2] 2f eb [2] 61 e7 [2] 6d ed [2] 7a e6 [2] 61 a8 [2] 5c }

  condition:
    any of them
}