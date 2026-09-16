rule TTP_XOR_MULT_DOSStub_c607 {
  strings:
    $key_c607 = { 92 6f [2] e6 77 [2] a1 75 [2] e6 64 [2] a8 68 [2] a4 62 [2] b3 69 [2] a8 27 [2] 95 }

  condition:
    any of them
}