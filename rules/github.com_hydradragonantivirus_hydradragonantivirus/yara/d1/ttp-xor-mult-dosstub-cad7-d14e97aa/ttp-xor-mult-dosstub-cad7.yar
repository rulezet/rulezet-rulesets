rule TTP_XOR_MULT_DOSStub_cad7 {
  strings:
    $key_cad7 = { 9e bf [2] ea a7 [2] ad a5 [2] ea b4 [2] a4 b8 [2] a8 b2 [2] bf b9 [2] a4 f7 [2] 99 }

  condition:
    any of them
}