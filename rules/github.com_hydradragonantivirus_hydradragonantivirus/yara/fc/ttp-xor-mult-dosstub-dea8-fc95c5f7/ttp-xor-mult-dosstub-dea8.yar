rule TTP_XOR_MULT_DOSStub_dea8 {
  strings:
    $key_dea8 = { 8a c0 [2] fe d8 [2] b9 da [2] fe cb [2] b0 c7 [2] bc cd [2] ab c6 [2] b0 88 [2] 8d }

  condition:
    any of them
}