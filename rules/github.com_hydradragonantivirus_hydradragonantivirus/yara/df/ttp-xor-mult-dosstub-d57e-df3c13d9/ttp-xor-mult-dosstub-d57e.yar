rule TTP_XOR_MULT_DOSStub_d57e {
  strings:
    $key_d57e = { 81 16 [2] f5 0e [2] b2 0c [2] f5 1d [2] bb 11 [2] b7 1b [2] a0 10 [2] bb 5e [2] 86 }

  condition:
    any of them
}