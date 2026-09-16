rule TTP_XOR_MULT_DOSStub_92a9 {
  strings:
    $key_92a9 = { c6 c1 [2] b2 d9 [2] f5 db [2] b2 ca [2] fc c6 [2] f0 cc [2] e7 c7 [2] fc 89 [2] c1 }

  condition:
    any of them
}