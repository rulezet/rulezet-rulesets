rule TTP_XOR_MULT_DOSStub_d87e {
  strings:
    $key_d87e = { 8c 16 [2] f8 0e [2] bf 0c [2] f8 1d [2] b6 11 [2] ba 1b [2] ad 10 [2] b6 5e [2] 8b }

  condition:
    any of them
}