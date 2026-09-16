rule TTP_XOR_MULT_DOSStub_d649 {
  strings:
    $key_d649 = { 82 21 [2] f6 39 [2] b1 3b [2] f6 2a [2] b8 26 [2] b4 2c [2] a3 27 [2] b8 69 [2] 85 }

  condition:
    any of them
}