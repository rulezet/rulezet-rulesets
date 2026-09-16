rule TTP_XOR_MULT_DOSStub_5fb3 {
  strings:
    $key_5fb3 = { 0b db [2] 7f c3 [2] 38 c1 [2] 7f d0 [2] 31 dc [2] 3d d6 [2] 2a dd [2] 31 93 [2] 0c }

  condition:
    any of them
}