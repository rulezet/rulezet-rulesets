rule TTP_XOR_MULT_DOSStub_d73e {
  strings:
    $key_d73e = { 83 56 [2] f7 4e [2] b0 4c [2] f7 5d [2] b9 51 [2] b5 5b [2] a2 50 [2] b9 1e [2] 84 }

  condition:
    any of them
}