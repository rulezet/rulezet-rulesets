rule TTP_XOR_MULT_DOSStub_d342 {
  strings:
    $key_d342 = { 87 2a [2] f3 32 [2] b4 30 [2] f3 21 [2] bd 2d [2] b1 27 [2] a6 2c [2] bd 62 [2] 80 }

  condition:
    any of them
}