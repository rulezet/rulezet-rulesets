rule TTP_XOR_MULT_DOSStub_d607 {
  strings:
    $key_d607 = { 82 6f [2] f6 77 [2] b1 75 [2] f6 64 [2] b8 68 [2] b4 62 [2] a3 69 [2] b8 27 [2] 85 }

  condition:
    any of them
}