rule TTP_XOR_MULT_DOSStub_d333 {
  strings:
    $key_d333 = { 87 5b [2] f3 43 [2] b4 41 [2] f3 50 [2] bd 5c [2] b1 56 [2] a6 5d [2] bd 13 [2] 80 }

  condition:
    any of them
}