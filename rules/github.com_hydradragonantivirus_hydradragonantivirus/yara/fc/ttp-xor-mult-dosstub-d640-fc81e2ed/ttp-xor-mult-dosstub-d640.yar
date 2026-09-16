rule TTP_XOR_MULT_DOSStub_d640 {
  strings:
    $key_d640 = { 82 28 [2] f6 30 [2] b1 32 [2] f6 23 [2] b8 2f [2] b4 25 [2] a3 2e [2] b8 60 [2] 85 }

  condition:
    any of them
}