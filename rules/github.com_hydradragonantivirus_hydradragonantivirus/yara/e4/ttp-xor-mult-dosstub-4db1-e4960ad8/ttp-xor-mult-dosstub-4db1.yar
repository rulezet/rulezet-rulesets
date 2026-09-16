rule TTP_XOR_MULT_DOSStub_4db1 {
  strings:
    $key_4db1 = { 19 d9 [2] 6d c1 [2] 2a c3 [2] 6d d2 [2] 23 de [2] 2f d4 [2] 38 df [2] 23 91 [2] 1e }

  condition:
    any of them
}