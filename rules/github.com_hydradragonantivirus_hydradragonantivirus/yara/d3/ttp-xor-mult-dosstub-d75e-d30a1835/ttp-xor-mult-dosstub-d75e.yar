rule TTP_XOR_MULT_DOSStub_d75e {
  strings:
    $key_d75e = { 83 36 [2] f7 2e [2] b0 2c [2] f7 3d [2] b9 31 [2] b5 3b [2] a2 30 [2] b9 7e [2] 84 }

  condition:
    any of them
}