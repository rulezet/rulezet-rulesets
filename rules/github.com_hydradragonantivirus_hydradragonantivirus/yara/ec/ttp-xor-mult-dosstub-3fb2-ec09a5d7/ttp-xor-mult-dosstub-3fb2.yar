rule TTP_XOR_MULT_DOSStub_3fb2 {
  strings:
    $key_3fb2 = { 6b da [2] 1f c2 [2] 58 c0 [2] 1f d1 [2] 51 dd [2] 5d d7 [2] 4a dc [2] 51 92 [2] 6c }

  condition:
    any of them
}