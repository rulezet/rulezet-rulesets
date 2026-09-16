rule TTP_XOR_MULT_DOSStub_d305 {
  strings:
    $key_d305 = { 87 6d [2] f3 75 [2] b4 77 [2] f3 66 [2] bd 6a [2] b1 60 [2] a6 6b [2] bd 25 [2] 80 }

  condition:
    any of them
}