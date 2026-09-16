rule TTP_XOR_MULT_DOSStub_3788 {
  strings:
    $key_3788 = { 63 e0 [2] 17 f8 [2] 50 fa [2] 17 eb [2] 59 e7 [2] 55 ed [2] 42 e6 [2] 59 a8 [2] 64 }

  condition:
    any of them
}