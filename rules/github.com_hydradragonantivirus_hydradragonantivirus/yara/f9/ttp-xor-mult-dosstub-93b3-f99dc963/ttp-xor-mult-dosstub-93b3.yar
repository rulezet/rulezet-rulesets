rule TTP_XOR_MULT_DOSStub_93b3 {
  strings:
    $key_93b3 = { c7 db [2] b3 c3 [2] f4 c1 [2] b3 d0 [2] fd dc [2] f1 d6 [2] e6 dd [2] fd 93 [2] c0 }

  condition:
    any of them
}