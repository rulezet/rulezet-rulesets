rule TTP_XOR_MULT_DOSStub_87b5 {
  strings:
    $key_87b5 = { d3 dd [2] a7 c5 [2] e0 c7 [2] a7 d6 [2] e9 da [2] e5 d0 [2] f2 db [2] e9 95 [2] d4 }

  condition:
    any of them
}