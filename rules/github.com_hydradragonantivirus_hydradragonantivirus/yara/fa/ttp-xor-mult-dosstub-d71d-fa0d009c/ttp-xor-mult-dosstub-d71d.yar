rule TTP_XOR_MULT_DOSStub_d71d {
  strings:
    $key_d71d = { 83 75 [2] f7 6d [2] b0 6f [2] f7 7e [2] b9 72 [2] b5 78 [2] a2 73 [2] b9 3d [2] 84 }

  condition:
    any of them
}