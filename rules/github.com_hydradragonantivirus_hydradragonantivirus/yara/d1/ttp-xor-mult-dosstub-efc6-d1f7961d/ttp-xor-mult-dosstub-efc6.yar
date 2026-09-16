rule TTP_XOR_MULT_DOSStub_efc6 {
  strings:
    $key_efc6 = { bb ae [2] cf b6 [2] 88 b4 [2] cf a5 [2] 81 a9 [2] 8d a3 [2] 9a a8 [2] 81 e6 [2] bc }

  condition:
    any of them
}