rule TTP_XOR_MULT_DOSStub_d388 {
  strings:
    $key_d388 = { 87 e0 [2] f3 f8 [2] b4 fa [2] f3 eb [2] bd e7 [2] b1 ed [2] a6 e6 [2] bd a8 [2] 80 }

  condition:
    any of them
}