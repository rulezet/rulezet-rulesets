rule TTP_XOR_MULT_DOSStub_91b5 {
  strings:
    $key_91b5 = { c5 dd [2] b1 c5 [2] f6 c7 [2] b1 d6 [2] ff da [2] f3 d0 [2] e4 db [2] ff 95 [2] c2 }

  condition:
    any of them
}