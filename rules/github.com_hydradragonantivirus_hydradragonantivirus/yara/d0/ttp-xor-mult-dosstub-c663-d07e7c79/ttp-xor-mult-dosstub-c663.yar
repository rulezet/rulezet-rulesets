rule TTP_XOR_MULT_DOSStub_c663 {
  strings:
    $key_c663 = { 92 0b [2] e6 13 [2] a1 11 [2] e6 00 [2] a8 0c [2] a4 06 [2] b3 0d [2] a8 43 [2] 95 }

  condition:
    any of them
}