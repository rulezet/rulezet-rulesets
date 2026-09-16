rule TTP_XOR_MULT_DOSStub_c3d9 {
  strings:
    $key_c3d9 = { 97 b1 [2] e3 a9 [2] a4 ab [2] e3 ba [2] ad b6 [2] a1 bc [2] b6 b7 [2] ad f9 [2] 90 }

  condition:
    any of them
}