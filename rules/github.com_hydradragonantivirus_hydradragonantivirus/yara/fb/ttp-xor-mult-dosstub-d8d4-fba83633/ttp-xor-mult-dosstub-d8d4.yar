rule TTP_XOR_MULT_DOSStub_d8d4 {
  strings:
    $key_d8d4 = { 8c bc [2] f8 a4 [2] bf a6 [2] f8 b7 [2] b6 bb [2] ba b1 [2] ad ba [2] b6 f4 [2] 8b }

  condition:
    any of them
}