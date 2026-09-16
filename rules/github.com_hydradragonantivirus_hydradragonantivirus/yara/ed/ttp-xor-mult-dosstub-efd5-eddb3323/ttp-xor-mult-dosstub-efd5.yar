rule TTP_XOR_MULT_DOSStub_efd5 {
  strings:
    $key_efd5 = { bb bd [2] cf a5 [2] 88 a7 [2] cf b6 [2] 81 ba [2] 8d b0 [2] 9a bb [2] 81 f5 [2] bc }

  condition:
    any of them
}