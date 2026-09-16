rule TTP_XOR_MULT_DOSStub_efc7 {
  strings:
    $key_efc7 = { bb af [2] cf b7 [2] 88 b5 [2] cf a4 [2] 81 a8 [2] 8d a2 [2] 9a a9 [2] 81 e7 [2] bc }

  condition:
    any of them
}