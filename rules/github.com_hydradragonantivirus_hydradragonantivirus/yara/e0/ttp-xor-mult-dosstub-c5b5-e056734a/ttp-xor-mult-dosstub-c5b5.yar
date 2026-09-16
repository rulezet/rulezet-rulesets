rule TTP_XOR_MULT_DOSStub_c5b5 {
  strings:
    $key_c5b5 = { 91 dd [2] e5 c5 [2] a2 c7 [2] e5 d6 [2] ab da [2] a7 d0 [2] b0 db [2] ab 95 [2] 96 }

  condition:
    any of them
}