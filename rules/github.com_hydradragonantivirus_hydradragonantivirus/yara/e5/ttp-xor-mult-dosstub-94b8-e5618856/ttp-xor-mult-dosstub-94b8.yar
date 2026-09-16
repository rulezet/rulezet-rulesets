rule TTP_XOR_MULT_DOSStub_94b8 {
  strings:
    $key_94b8 = { c0 d0 [2] b4 c8 [2] f3 ca [2] b4 db [2] fa d7 [2] f6 dd [2] e1 d6 [2] fa 98 [2] c7 }

  condition:
    any of them
}