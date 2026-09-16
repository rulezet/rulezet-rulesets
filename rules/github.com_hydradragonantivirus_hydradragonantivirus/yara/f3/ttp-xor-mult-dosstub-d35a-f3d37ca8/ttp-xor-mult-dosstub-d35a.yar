rule TTP_XOR_MULT_DOSStub_d35a {
  strings:
    $key_d35a = { 87 32 [2] f3 2a [2] b4 28 [2] f3 39 [2] bd 35 [2] b1 3f [2] a6 34 [2] bd 7a [2] 80 }

  condition:
    any of them
}