rule TTP_XOR_MULT_DOSStub_7e88 {
  strings:
    $key_7e88 = { 2a e0 [2] 5e f8 [2] 19 fa [2] 5e eb [2] 10 e7 [2] 1c ed [2] 0b e6 [2] 10 a8 [2] 2d }

  condition:
    any of them
}