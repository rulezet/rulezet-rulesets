rule TTP_XOR_MULT_DOSStub_c3d2 {
  strings:
    $key_c3d2 = { 97 ba [2] e3 a2 [2] a4 a0 [2] e3 b1 [2] ad bd [2] a1 b7 [2] b6 bc [2] ad f2 [2] 90 }

  condition:
    any of them
}