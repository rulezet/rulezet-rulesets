rule TTP_XOR_MULT_DOSStub_d601 {
  strings:
    $key_d601 = { 82 69 [2] f6 71 [2] b1 73 [2] f6 62 [2] b8 6e [2] b4 64 [2] a3 6f [2] b8 21 [2] 85 }

  condition:
    any of them
}