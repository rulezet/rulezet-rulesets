rule TTP_XOR_MULT_DOSStub_0e88 {
  strings:
    $key_0e88 = { 5a e0 [2] 2e f8 [2] 69 fa [2] 2e eb [2] 60 e7 [2] 6c ed [2] 7b e6 [2] 60 a8 [2] 5d }

  condition:
    any of them
}