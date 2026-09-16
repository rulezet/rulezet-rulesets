rule TTP_XOR_MULT_DOSStub_bcb5 {
  strings:
    $key_bcb5 = { e8 dd [2] 9c c5 [2] db c7 [2] 9c d6 [2] d2 da [2] de d0 [2] c9 db [2] d2 95 [2] ef }

  condition:
    any of them
}