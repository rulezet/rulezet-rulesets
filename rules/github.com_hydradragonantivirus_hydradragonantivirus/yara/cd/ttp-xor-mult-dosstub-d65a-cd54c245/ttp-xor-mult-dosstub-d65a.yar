rule TTP_XOR_MULT_DOSStub_d65a {
  strings:
    $key_d65a = { 82 32 [2] f6 2a [2] b1 28 [2] f6 39 [2] b8 35 [2] b4 3f [2] a3 34 [2] b8 7a [2] 85 }

  condition:
    any of them
}