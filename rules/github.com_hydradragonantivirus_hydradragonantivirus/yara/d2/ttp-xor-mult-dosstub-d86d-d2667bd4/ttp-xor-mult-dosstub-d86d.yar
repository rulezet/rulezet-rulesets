rule TTP_XOR_MULT_DOSStub_d86d {
  strings:
    $key_d86d = { 8c 05 [2] f8 1d [2] bf 1f [2] f8 0e [2] b6 02 [2] ba 08 [2] ad 03 [2] b6 4d [2] 8b }

  condition:
    any of them
}