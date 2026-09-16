rule TTP_XOR_MULT_DOSStub_d678 {
  strings:
    $key_d678 = { 82 10 [2] f6 08 [2] b1 0a [2] f6 1b [2] b8 17 [2] b4 1d [2] a3 16 [2] b8 58 [2] 85 }

  condition:
    any of them
}