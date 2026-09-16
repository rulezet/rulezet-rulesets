rule TTP_XOR_MULT_DOSStub_d53e {
  strings:
    $key_d53e = { 81 56 [2] f5 4e [2] b2 4c [2] f5 5d [2] bb 51 [2] b7 5b [2] a0 50 [2] bb 1e [2] 86 }

  condition:
    any of them
}