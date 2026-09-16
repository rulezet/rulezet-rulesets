rule TTP_XOR_MULT_DOSStub_d372 {
  strings:
    $key_d372 = { 87 1a [2] f3 02 [2] b4 00 [2] f3 11 [2] bd 1d [2] b1 17 [2] a6 1c [2] bd 52 [2] 80 }

  condition:
    any of them
}