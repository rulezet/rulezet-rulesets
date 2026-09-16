rule TTP_XOR_MULT_DOSStub_1e88 {
  strings:
    $key_1e88 = { 4a e0 [2] 3e f8 [2] 79 fa [2] 3e eb [2] 70 e7 [2] 7c ed [2] 6b e6 [2] 70 a8 [2] 4d }

  condition:
    any of them
}