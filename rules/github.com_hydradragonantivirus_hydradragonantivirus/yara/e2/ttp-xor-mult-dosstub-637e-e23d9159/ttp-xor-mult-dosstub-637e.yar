rule TTP_XOR_MULT_DOSStub_637e {
  strings:
    $key_637e = { 37 16 [2] 43 0e [2] 04 0c [2] 43 1d [2] 0d 11 [2] 01 1b [2] 16 10 [2] 0d 5e [2] 30 }

  condition:
    any of them
}