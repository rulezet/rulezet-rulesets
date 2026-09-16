rule TTP_XOR_MULT_DOSStub_d831 {
  strings:
    $key_d831 = { 8c 59 [2] f8 41 [2] bf 43 [2] f8 52 [2] b6 5e [2] ba 54 [2] ad 5f [2] b6 11 [2] 8b }

  condition:
    any of them
}