rule TTP_XOR_MULT_DOSStub_8ca2 {
  strings:
    $key_8ca2 = { d8 ca [2] ac d2 [2] eb d0 [2] ac c1 [2] e2 cd [2] ee c7 [2] f9 cc [2] e2 82 [2] df }

  condition:
    any of them
}