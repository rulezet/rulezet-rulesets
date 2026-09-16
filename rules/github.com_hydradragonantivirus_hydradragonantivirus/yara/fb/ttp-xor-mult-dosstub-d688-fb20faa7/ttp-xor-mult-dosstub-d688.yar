rule TTP_XOR_MULT_DOSStub_d688 {
  strings:
    $key_d688 = { 82 e0 [2] f6 f8 [2] b1 fa [2] f6 eb [2] b8 e7 [2] b4 ed [2] a3 e6 [2] b8 a8 [2] 85 }

  condition:
    any of them
}