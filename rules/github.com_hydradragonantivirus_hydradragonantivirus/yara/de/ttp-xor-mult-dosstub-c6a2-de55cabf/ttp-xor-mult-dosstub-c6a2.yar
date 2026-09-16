rule TTP_XOR_MULT_DOSStub_c6a2 {
  strings:
    $key_c6a2 = { 92 ca [2] e6 d2 [2] a1 d0 [2] e6 c1 [2] a8 cd [2] a4 c7 [2] b3 cc [2] a8 82 [2] 95 }

  condition:
    any of them
}