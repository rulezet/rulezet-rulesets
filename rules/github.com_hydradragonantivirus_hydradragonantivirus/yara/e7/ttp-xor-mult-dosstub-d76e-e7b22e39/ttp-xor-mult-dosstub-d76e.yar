rule TTP_XOR_MULT_DOSStub_d76e {
  strings:
    $key_d76e = { 83 06 [2] f7 1e [2] b0 1c [2] f7 0d [2] b9 01 [2] b5 0b [2] a2 00 [2] b9 4e [2] 84 }

  condition:
    any of them
}