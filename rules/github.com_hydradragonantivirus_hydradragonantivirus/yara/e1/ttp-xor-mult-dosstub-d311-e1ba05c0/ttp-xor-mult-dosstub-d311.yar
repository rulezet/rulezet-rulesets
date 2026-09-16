rule TTP_XOR_MULT_DOSStub_d311 {
  strings:
    $key_d311 = { 87 79 [2] f3 61 [2] b4 63 [2] f3 72 [2] bd 7e [2] b1 74 [2] a6 7f [2] bd 31 [2] 80 }

  condition:
    any of them
}