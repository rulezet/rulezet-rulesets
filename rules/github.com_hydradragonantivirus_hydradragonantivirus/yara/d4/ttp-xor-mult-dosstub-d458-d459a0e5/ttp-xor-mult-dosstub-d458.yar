rule TTP_XOR_MULT_DOSStub_d458 {
  strings:
    $key_d458 = { 80 30 [2] f4 28 [2] b3 2a [2] f4 3b [2] ba 37 [2] b6 3d [2] a1 36 [2] ba 78 [2] 87 }

  condition:
    any of them
}