rule TTP_XOR_MULT_DOSStub_d758 {
  strings:
    $key_d758 = { 83 30 [2] f7 28 [2] b0 2a [2] f7 3b [2] b9 37 [2] b5 3d [2] a2 36 [2] b9 78 [2] 84 }

  condition:
    any of them
}