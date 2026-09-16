rule TTP_XOR_MULT_DOSStub_d0b5 {
  strings:
    $key_d0b5 = { 84 dd [2] f0 c5 [2] b7 c7 [2] f0 d6 [2] be da [2] b2 d0 [2] a5 db [2] be 95 [2] 83 }

  condition:
    any of them
}