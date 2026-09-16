rule TTP_XOR_MULT_DOSStub_93b5 {
  strings:
    $key_93b5 = { c7 dd [2] b3 c5 [2] f4 c7 [2] b3 d6 [2] fd da [2] f1 d0 [2] e6 db [2] fd 95 [2] c0 }

  condition:
    any of them
}