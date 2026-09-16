rule TTP_XOR_MULT_DOSStub_d6f1 {
  strings:
    $key_d6f1 = { 82 99 [2] f6 81 [2] b1 83 [2] f6 92 [2] b8 9e [2] b4 94 [2] a3 9f [2] b8 d1 [2] 85 }

  condition:
    any of them
}