rule TTP_XOR_MULT_DOSStub_7db4 {
  strings:
    $key_7db4 = { 29 dc [2] 5d c4 [2] 1a c6 [2] 5d d7 [2] 13 db [2] 1f d1 [2] 08 da [2] 13 94 [2] 2e }

  condition:
    any of them
}