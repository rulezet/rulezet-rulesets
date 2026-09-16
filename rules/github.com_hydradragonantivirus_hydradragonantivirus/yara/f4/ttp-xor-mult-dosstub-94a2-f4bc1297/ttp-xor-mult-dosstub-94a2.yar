rule TTP_XOR_MULT_DOSStub_94a2 {
  strings:
    $key_94a2 = { c0 ca [2] b4 d2 [2] f3 d0 [2] b4 c1 [2] fa cd [2] f6 c7 [2] e1 cc [2] fa 82 [2] c7 }

  condition:
    any of them
}