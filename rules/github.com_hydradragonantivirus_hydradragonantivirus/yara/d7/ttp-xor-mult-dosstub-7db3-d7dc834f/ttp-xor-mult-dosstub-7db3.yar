rule TTP_XOR_MULT_DOSStub_7db3 {
  strings:
    $key_7db3 = { 29 db [2] 5d c3 [2] 1a c1 [2] 5d d0 [2] 13 dc [2] 1f d6 [2] 08 dd [2] 13 93 [2] 2e }

  condition:
    any of them
}