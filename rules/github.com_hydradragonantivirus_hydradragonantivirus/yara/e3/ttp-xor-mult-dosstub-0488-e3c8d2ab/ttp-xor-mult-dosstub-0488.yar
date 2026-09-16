rule TTP_XOR_MULT_DOSStub_0488 {
  strings:
    $key_0488 = { 50 e0 [2] 24 f8 [2] 63 fa [2] 24 eb [2] 6a e7 [2] 66 ed [2] 71 e6 [2] 6a a8 [2] 57 }

  condition:
    any of them
}