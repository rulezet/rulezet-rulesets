rule TTP_XOR_MULT_DOSStub_c7a2 {
  strings:
    $key_c7a2 = { 93 ca [2] e7 d2 [2] a0 d0 [2] e7 c1 [2] a9 cd [2] a5 c7 [2] b2 cc [2] a9 82 [2] 94 }

  condition:
    any of them
}