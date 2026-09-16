rule TTP_XOR_MULT_DOSStub_d322 {
  strings:
    $key_d322 = { 87 4a [2] f3 52 [2] b4 50 [2] f3 41 [2] bd 4d [2] b1 47 [2] a6 4c [2] bd 02 [2] 80 }

  condition:
    any of them
}