rule TTP_XOR_MULT_DOSStub_3fb3 {
  strings:
    $key_3fb3 = { 6b db [2] 1f c3 [2] 58 c1 [2] 1f d0 [2] 51 dc [2] 5d d6 [2] 4a dd [2] 51 93 [2] 6c }

  condition:
    any of them
}