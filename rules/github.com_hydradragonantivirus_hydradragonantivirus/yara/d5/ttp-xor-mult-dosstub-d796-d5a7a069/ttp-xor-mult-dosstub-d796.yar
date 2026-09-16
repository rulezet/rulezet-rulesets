rule TTP_XOR_MULT_DOSStub_d796 {
  strings:
    $key_d796 = { 83 fe [2] f7 e6 [2] b0 e4 [2] f7 f5 [2] b9 f9 [2] b5 f3 [2] a2 f8 [2] b9 b6 [2] 84 }

  condition:
    any of them
}