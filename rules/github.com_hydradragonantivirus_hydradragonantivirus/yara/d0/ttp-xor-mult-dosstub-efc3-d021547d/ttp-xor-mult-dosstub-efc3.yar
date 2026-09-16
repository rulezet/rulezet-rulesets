rule TTP_XOR_MULT_DOSStub_efc3 {
  strings:
    $key_efc3 = { bb ab [2] cf b3 [2] 88 b1 [2] cf a0 [2] 81 ac [2] 8d a6 [2] 9a ad [2] 81 e3 [2] bc }

  condition:
    any of them
}