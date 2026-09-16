rule TTP_XOR_MULT_DOSStub_d34a {
  strings:
    $key_d34a = { 87 22 [2] f3 3a [2] b4 38 [2] f3 29 [2] bd 25 [2] b1 2f [2] a6 24 [2] bd 6a [2] 80 }

  condition:
    any of them
}