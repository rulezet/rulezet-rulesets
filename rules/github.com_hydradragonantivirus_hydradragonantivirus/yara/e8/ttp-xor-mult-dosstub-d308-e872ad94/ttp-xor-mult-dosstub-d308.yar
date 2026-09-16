rule TTP_XOR_MULT_DOSStub_d308 {
  strings:
    $key_d308 = { 87 60 [2] f3 78 [2] b4 7a [2] f3 6b [2] bd 67 [2] b1 6d [2] a6 66 [2] bd 28 [2] 80 }

  condition:
    any of them
}