rule TTP_XOR_MULT_DOSStub_7db1 {
  strings:
    $key_7db1 = { 29 d9 [2] 5d c1 [2] 1a c3 [2] 5d d2 [2] 13 de [2] 1f d4 [2] 08 df [2] 13 91 [2] 2e }

  condition:
    any of them
}