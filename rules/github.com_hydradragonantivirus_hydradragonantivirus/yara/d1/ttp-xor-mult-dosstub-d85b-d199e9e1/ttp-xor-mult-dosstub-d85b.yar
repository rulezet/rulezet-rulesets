rule TTP_XOR_MULT_DOSStub_d85b {
  strings:
    $key_d85b = { 8c 33 [2] f8 2b [2] bf 29 [2] f8 38 [2] b6 34 [2] ba 3e [2] ad 35 [2] b6 7b [2] 8b }

  condition:
    any of them
}