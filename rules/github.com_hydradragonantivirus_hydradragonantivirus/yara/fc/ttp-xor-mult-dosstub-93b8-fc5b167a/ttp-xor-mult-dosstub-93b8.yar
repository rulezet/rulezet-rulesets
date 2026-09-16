rule TTP_XOR_MULT_DOSStub_93b8 {
  strings:
    $key_93b8 = { c7 d0 [2] b3 c8 [2] f4 ca [2] b3 db [2] fd d7 [2] f1 dd [2] e6 d6 [2] fd 98 [2] c0 }

  condition:
    any of them
}