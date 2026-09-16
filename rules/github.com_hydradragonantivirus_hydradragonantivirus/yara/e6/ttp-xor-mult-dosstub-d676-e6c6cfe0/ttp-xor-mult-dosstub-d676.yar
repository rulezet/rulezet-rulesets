rule TTP_XOR_MULT_DOSStub_d676 {
  strings:
    $key_d676 = { 82 1e [2] f6 06 [2] b1 04 [2] f6 15 [2] b8 19 [2] b4 13 [2] a3 18 [2] b8 56 [2] 85 }

  condition:
    any of them
}