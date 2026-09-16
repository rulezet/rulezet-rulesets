rule TTP_XOR_MULT_DOSStub_d788 {
  strings:
    $key_d788 = { 83 e0 [2] f7 f8 [2] b0 fa [2] f7 eb [2] b9 e7 [2] b5 ed [2] a2 e6 [2] b9 a8 [2] 84 }

  condition:
    any of them
}