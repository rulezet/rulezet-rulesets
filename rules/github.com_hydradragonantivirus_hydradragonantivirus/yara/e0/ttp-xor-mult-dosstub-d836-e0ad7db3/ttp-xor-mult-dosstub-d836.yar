rule TTP_XOR_MULT_DOSStub_d836 {
  strings:
    $key_d836 = { 8c 5e [2] f8 46 [2] bf 44 [2] f8 55 [2] b6 59 [2] ba 53 [2] ad 58 [2] b6 16 [2] 8b }

  condition:
    any of them
}