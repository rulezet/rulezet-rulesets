rule TTP_XOR_MULT_DOSStub_c397 {
  strings:
    $key_c397 = { 97 ff [2] e3 e7 [2] a4 e5 [2] e3 f4 [2] ad f8 [2] a1 f2 [2] b6 f9 [2] ad b7 [2] 90 }

  condition:
    any of them
}