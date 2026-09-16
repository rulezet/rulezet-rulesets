rule TTP_XOR_MULT_DOSStub_4f95 {
  strings:
    $key_4f95 = { 1b fd [2] 6f e5 [2] 28 e7 [2] 6f f6 [2] 21 fa [2] 2d f0 [2] 3a fb [2] 21 b5 [2] 1c }

  condition:
    any of them
}