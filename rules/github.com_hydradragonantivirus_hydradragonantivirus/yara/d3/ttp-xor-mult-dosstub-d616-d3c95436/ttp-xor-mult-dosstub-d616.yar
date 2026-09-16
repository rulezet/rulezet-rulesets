rule TTP_XOR_MULT_DOSStub_d616 {
  strings:
    $key_d616 = { 82 7e [2] f6 66 [2] b1 64 [2] f6 75 [2] b8 79 [2] b4 73 [2] a3 78 [2] b8 36 [2] 85 }

  condition:
    any of them
}