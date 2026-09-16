rule TTP_XOR_MULT_DOSStub_d316 {
  strings:
    $key_d316 = { 87 7e [2] f3 66 [2] b4 64 [2] f3 75 [2] bd 79 [2] b1 73 [2] a6 78 [2] bd 36 [2] 80 }

  condition:
    any of them
}