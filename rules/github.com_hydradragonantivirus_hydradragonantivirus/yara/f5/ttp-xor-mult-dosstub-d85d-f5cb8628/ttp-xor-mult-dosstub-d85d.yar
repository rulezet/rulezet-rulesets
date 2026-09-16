rule TTP_XOR_MULT_DOSStub_d85d {
  strings:
    $key_d85d = { 8c 35 [2] f8 2d [2] bf 2f [2] f8 3e [2] b6 32 [2] ba 38 [2] ad 33 [2] b6 7d [2] 8b }

  condition:
    any of them
}