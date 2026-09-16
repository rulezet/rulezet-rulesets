rule TTP_XOR_MULT_DOSStub_d661 {
  strings:
    $key_d661 = { 82 09 [2] f6 11 [2] b1 13 [2] f6 02 [2] b8 0e [2] b4 04 [2] a3 0f [2] b8 41 [2] 85 }

  condition:
    any of them
}