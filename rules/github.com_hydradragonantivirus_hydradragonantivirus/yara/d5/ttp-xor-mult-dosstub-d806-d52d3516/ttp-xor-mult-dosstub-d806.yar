rule TTP_XOR_MULT_DOSStub_d806 {
  strings:
    $key_d806 = { 8c 6e [2] f8 76 [2] bf 74 [2] f8 65 [2] b6 69 [2] ba 63 [2] ad 68 [2] b6 26 [2] 8b }

  condition:
    any of them
}