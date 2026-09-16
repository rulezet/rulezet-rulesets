rule TTP_XOR_MULT_DOSStub_6f88 {
  strings:
    $key_6f88 = { 3b e0 [2] 4f f8 [2] 08 fa [2] 4f eb [2] 01 e7 [2] 0d ed [2] 1a e6 [2] 01 a8 [2] 3c }

  condition:
    any of them
}