rule TTP_XOR_MULT_DOSStub_1db1 {
  strings:
    $key_1db1 = { 49 d9 [2] 3d c1 [2] 7a c3 [2] 3d d2 [2] 73 de [2] 7f d4 [2] 68 df [2] 73 91 [2] 4e }

  condition:
    any of them
}