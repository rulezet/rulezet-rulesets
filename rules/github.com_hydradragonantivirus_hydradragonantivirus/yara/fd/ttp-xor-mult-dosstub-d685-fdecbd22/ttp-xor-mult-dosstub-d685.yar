rule TTP_XOR_MULT_DOSStub_d685 {
  strings:
    $key_d685 = { 82 ed [2] f6 f5 [2] b1 f7 [2] f6 e6 [2] b8 ea [2] b4 e0 [2] a3 eb [2] b8 a5 [2] 85 }

  condition:
    any of them
}