rule TTP_XOR_MULT_DOSStub_d302 {
  strings:
    $key_d302 = { 87 6a [2] f3 72 [2] b4 70 [2] f3 61 [2] bd 6d [2] b1 67 [2] a6 6c [2] bd 22 [2] 80 }

  condition:
    any of them
}