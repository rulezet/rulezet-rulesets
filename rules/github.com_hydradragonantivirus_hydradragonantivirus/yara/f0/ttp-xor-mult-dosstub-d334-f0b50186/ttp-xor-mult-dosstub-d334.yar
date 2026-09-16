rule TTP_XOR_MULT_DOSStub_d334 {
  strings:
    $key_d334 = { 87 5c [2] f3 44 [2] b4 46 [2] f3 57 [2] bd 5b [2] b1 51 [2] a6 5a [2] bd 14 [2] 80 }

  condition:
    any of them
}