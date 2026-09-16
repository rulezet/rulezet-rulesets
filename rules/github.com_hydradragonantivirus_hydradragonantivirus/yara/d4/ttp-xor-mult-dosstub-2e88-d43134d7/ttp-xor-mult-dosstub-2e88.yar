rule TTP_XOR_MULT_DOSStub_2e88 {
  strings:
    $key_2e88 = { 7a e0 [2] 0e f8 [2] 49 fa [2] 0e eb [2] 40 e7 [2] 4c ed [2] 5b e6 [2] 40 a8 [2] 7d }

  condition:
    any of them
}