rule TTP_XOR_MULT_DOSStub_97a2 {
  strings:
    $key_97a2 = { c3 ca [2] b7 d2 [2] f0 d0 [2] b7 c1 [2] f9 cd [2] f5 c7 [2] e2 cc [2] f9 82 [2] c4 }

  condition:
    any of them
}