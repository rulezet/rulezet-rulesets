rule TTP_XOR_MULT_DOSStub_4488 {
  strings:
    $key_4488 = { 10 e0 [2] 64 f8 [2] 23 fa [2] 64 eb [2] 2a e7 [2] 26 ed [2] 31 e6 [2] 2a a8 [2] 17 }

  condition:
    any of them
}