rule TTP_XOR_MULT_DOSStub_d155 {
  strings:
    $key_d155 = { 85 3d [2] f1 25 [2] b6 27 [2] f1 36 [2] bf 3a [2] b3 30 [2] a4 3b [2] bf 75 [2] 82 }

  condition:
    any of them
}