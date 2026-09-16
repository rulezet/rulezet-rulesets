rule TTP_XOR_MULT_DOSStub_d698 {
  strings:
    $key_d698 = { 82 f0 [2] f6 e8 [2] b1 ea [2] f6 fb [2] b8 f7 [2] b4 fd [2] a3 f6 [2] b8 b8 [2] 85 }

  condition:
    any of them
}