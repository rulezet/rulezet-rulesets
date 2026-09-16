rule TTP_XOR_MULT_DOSStub_80b3 {
  strings:
    $key_80b3 = { d4 db [2] a0 c3 [2] e7 c1 [2] a0 d0 [2] ee dc [2] e2 d6 [2] f5 dd [2] ee 93 [2] d3 }

  condition:
    any of them
}