rule TTP_XOR_MULT_DOSStub_c3a9 {
  strings:
    $key_c3a9 = { 97 c1 [2] e3 d9 [2] a4 db [2] e3 ca [2] ad c6 [2] a1 cc [2] b6 c7 [2] ad 89 [2] 90 }

  condition:
    any of them
}