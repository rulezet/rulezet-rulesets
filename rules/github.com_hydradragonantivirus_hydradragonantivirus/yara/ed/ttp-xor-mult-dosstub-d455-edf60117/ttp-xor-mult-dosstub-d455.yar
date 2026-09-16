rule TTP_XOR_MULT_DOSStub_d455 {
  strings:
    $key_d455 = { 80 3d [2] f4 25 [2] b3 27 [2] f4 36 [2] ba 3a [2] b6 30 [2] a1 3b [2] ba 75 [2] 87 }

  condition:
    any of them
}