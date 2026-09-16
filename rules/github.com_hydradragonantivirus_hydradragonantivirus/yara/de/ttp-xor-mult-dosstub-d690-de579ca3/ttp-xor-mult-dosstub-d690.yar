rule TTP_XOR_MULT_DOSStub_d690 {
  strings:
    $key_d690 = { 82 f8 [2] f6 e0 [2] b1 e2 [2] f6 f3 [2] b8 ff [2] b4 f5 [2] a3 fe [2] b8 b0 [2] 85 }

  condition:
    any of them
}