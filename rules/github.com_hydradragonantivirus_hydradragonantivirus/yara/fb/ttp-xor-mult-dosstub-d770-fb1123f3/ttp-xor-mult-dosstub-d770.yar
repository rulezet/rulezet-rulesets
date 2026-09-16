rule TTP_XOR_MULT_DOSStub_d770 {
  strings:
    $key_d770 = { 83 18 [2] f7 00 [2] b0 02 [2] f7 13 [2] b9 1f [2] b5 15 [2] a2 1e [2] b9 50 [2] 84 }

  condition:
    any of them
}