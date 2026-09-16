rule TTP_XOR_MULT_DOSStub_1388 {
  strings:
    $key_1388 = { 47 e0 [2] 33 f8 [2] 74 fa [2] 33 eb [2] 7d e7 [2] 71 ed [2] 66 e6 [2] 7d a8 [2] 40 }

  condition:
    any of them
}