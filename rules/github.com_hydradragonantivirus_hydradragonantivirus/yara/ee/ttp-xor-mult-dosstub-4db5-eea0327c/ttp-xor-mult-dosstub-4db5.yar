rule TTP_XOR_MULT_DOSStub_4db5 {
  strings:
    $key_4db5 = { 19 dd [2] 6d c5 [2] 2a c7 [2] 6d d6 [2] 23 da [2] 2f d0 [2] 38 db [2] 23 95 [2] 1e }

  condition:
    any of them
}