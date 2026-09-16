rule TTP_XOR_MULT_DOSStub_d379 {
  strings:
    $key_d379 = { 87 11 [2] f3 09 [2] b4 0b [2] f3 1a [2] bd 16 [2] b1 1c [2] a6 17 [2] bd 59 [2] 80 }

  condition:
    any of them
}