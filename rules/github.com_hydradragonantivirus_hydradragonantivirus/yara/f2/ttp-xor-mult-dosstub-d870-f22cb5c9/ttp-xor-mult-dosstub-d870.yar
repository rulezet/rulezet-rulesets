rule TTP_XOR_MULT_DOSStub_d870 {
  strings:
    $key_d870 = { 8c 18 [2] f8 00 [2] bf 02 [2] f8 13 [2] b6 1f [2] ba 15 [2] ad 1e [2] b6 50 [2] 8b }

  condition:
    any of them
}