rule TTP_XOR_MULT_DOSStub_d675 {
  strings:
    $key_d675 = { 82 1d [2] f6 05 [2] b1 07 [2] f6 16 [2] b8 1a [2] b4 10 [2] a3 1b [2] b8 55 [2] 85 }

  condition:
    any of them
}