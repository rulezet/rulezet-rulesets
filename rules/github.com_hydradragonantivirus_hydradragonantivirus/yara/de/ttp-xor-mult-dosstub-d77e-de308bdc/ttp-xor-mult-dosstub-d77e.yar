rule TTP_XOR_MULT_DOSStub_d77e {
  strings:
    $key_d77e = { 83 16 [2] f7 0e [2] b0 0c [2] f7 1d [2] b9 11 [2] b5 1b [2] a2 10 [2] b9 5e [2] 84 }

  condition:
    any of them
}