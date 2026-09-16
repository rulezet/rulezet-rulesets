rule TTP_XOR_MULT_DOSStub_d385 {
  strings:
    $key_d385 = { 87 ed [2] f3 f5 [2] b4 f7 [2] f3 e6 [2] bd ea [2] b1 e0 [2] a6 eb [2] bd a5 [2] 80 }

  condition:
    any of them
}