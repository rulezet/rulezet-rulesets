rule TTP_XOR_MULT_DOSStub_7f88 {
  strings:
    $key_7f88 = { 2b e0 [2] 5f f8 [2] 18 fa [2] 5f eb [2] 11 e7 [2] 1d ed [2] 0a e6 [2] 11 a8 [2] 2c }

  condition:
    any of them
}