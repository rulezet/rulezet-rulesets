rule TTP_XOR_MULT_DOSStub_97b8 {
  strings:
    $key_97b8 = { c3 d0 [2] b7 c8 [2] f0 ca [2] b7 db [2] f9 d7 [2] f5 dd [2] e2 d6 [2] f9 98 [2] c4 }

  condition:
    any of them
}