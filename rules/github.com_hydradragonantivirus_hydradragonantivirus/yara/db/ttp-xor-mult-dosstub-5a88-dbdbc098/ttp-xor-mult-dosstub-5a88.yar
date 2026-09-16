rule TTP_XOR_MULT_DOSStub_5a88 {
  strings:
    $key_5a88 = { 0e e0 [2] 7a f8 [2] 3d fa [2] 7a eb [2] 34 e7 [2] 38 ed [2] 2f e6 [2] 34 a8 [2] 09 }

  condition:
    any of them
}