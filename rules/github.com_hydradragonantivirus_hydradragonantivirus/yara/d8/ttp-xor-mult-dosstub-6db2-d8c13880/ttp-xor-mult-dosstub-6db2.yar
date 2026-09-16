rule TTP_XOR_MULT_DOSStub_6db2 {
  strings:
    $key_6db2 = { 39 da [2] 4d c2 [2] 0a c0 [2] 4d d1 [2] 03 dd [2] 0f d7 [2] 18 dc [2] 03 92 [2] 3e }

  condition:
    any of them
}