rule TTP_XOR_MULT_DOSStub_d651 {
  strings:
    $key_d651 = { 82 39 [2] f6 21 [2] b1 23 [2] f6 32 [2] b8 3e [2] b4 34 [2] a3 3f [2] b8 71 [2] 85 }

  condition:
    any of them
}