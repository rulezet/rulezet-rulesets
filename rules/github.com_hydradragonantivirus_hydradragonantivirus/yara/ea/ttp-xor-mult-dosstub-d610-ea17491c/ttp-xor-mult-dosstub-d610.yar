rule TTP_XOR_MULT_DOSStub_d610 {
  strings:
    $key_d610 = { 82 78 [2] f6 60 [2] b1 62 [2] f6 73 [2] b8 7f [2] b4 75 [2] a3 7e [2] b8 30 [2] 85 }

  condition:
    any of them
}