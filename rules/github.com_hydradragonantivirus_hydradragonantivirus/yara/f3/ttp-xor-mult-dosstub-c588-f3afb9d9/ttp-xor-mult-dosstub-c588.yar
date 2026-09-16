rule TTP_XOR_MULT_DOSStub_c588 {
  strings:
    $key_c588 = { 91 e0 [2] e5 f8 [2] a2 fa [2] e5 eb [2] ab e7 [2] a7 ed [2] b0 e6 [2] ab a8 [2] 96 }

  condition:
    any of them
}