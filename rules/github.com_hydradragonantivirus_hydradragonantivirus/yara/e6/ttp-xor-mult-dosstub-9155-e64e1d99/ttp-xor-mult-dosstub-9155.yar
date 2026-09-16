rule TTP_XOR_MULT_DOSStub_9155 {
  strings:
    $key_9155 = { c5 3d [2] b1 25 [2] f6 27 [2] b1 36 [2] ff 3a [2] f3 30 [2] e4 3b [2] ff 75 [2] c2 }

  condition:
    any of them
}