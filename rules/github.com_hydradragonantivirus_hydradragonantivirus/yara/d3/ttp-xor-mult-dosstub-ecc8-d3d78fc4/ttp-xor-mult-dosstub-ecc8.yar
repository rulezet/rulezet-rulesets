rule TTP_XOR_MULT_DOSStub_ecc8 {
  strings:
    $key_ecc8 = { b8 a0 [2] cc b8 [2] 8b ba [2] cc ab [2] 82 a7 [2] 8e ad [2] 99 a6 [2] 82 e8 [2] bf }

  condition:
    any of them
}