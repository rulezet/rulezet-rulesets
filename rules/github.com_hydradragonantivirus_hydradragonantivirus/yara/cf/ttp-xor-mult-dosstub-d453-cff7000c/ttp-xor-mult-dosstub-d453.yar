rule TTP_XOR_MULT_DOSStub_d453 {
  strings:
    $key_d453 = { 80 3b [2] f4 23 [2] b3 21 [2] f4 30 [2] ba 3c [2] b6 36 [2] a1 3d [2] ba 73 [2] 87 }

  condition:
    any of them
}