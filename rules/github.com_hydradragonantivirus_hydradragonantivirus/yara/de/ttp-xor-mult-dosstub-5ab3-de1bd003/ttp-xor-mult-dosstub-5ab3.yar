rule TTP_XOR_MULT_DOSStub_5ab3 {
  strings:
    $key_5ab3 = { 0e db [2] 7a c3 [2] 3d c1 [2] 7a d0 [2] 34 dc [2] 38 d6 [2] 2f dd [2] 34 93 [2] 09 }

  condition:
    any of them
}