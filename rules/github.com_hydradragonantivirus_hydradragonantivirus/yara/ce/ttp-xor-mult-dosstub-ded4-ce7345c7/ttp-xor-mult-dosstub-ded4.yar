rule TTP_XOR_MULT_DOSStub_ded4 {
  strings:
    $key_ded4 = { 8a bc [2] fe a4 [2] b9 a6 [2] fe b7 [2] b0 bb [2] bc b1 [2] ab ba [2] b0 f4 [2] 8d }

  condition:
    any of them
}