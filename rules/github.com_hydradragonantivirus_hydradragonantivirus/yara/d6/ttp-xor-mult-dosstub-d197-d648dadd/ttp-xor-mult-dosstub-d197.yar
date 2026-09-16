rule TTP_XOR_MULT_DOSStub_d197 {
  strings:
    $key_d197 = { 85 ff [2] f1 e7 [2] b6 e5 [2] f1 f4 [2] bf f8 [2] b3 f2 [2] a4 f9 [2] bf b7 [2] 82 }

  condition:
    any of them
}