rule TTP_XOR_MULT_DOSStub_d377 {
  strings:
    $key_d377 = { 87 1f [2] f3 07 [2] b4 05 [2] f3 14 [2] bd 18 [2] b1 12 [2] a6 19 [2] bd 57 [2] 80 }

  condition:
    any of them
}