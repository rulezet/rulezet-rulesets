rule TTP_XOR_MULT_DOSStub_d381 {
  strings:
    $key_d381 = { 87 e9 [2] f3 f1 [2] b4 f3 [2] f3 e2 [2] bd ee [2] b1 e4 [2] a6 ef [2] bd a1 [2] 80 }

  condition:
    any of them
}