rule TTP_XOR_MULT_DOSStub_1688 {
  strings:
    $key_1688 = { 42 e0 [2] 36 f8 [2] 71 fa [2] 36 eb [2] 78 e7 [2] 74 ed [2] 63 e6 [2] 78 a8 [2] 45 }

  condition:
    any of them
}