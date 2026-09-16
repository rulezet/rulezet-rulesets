rule TTP_XOR_MULT_DOSStub_457e {
  strings:
    $key_457e = { 11 16 [2] 65 0e [2] 22 0c [2] 65 1d [2] 2b 11 [2] 27 1b [2] 30 10 [2] 2b 5e [2] 16 }

  condition:
    any of them
}