rule TTP_XOR_MULT_DOSStub_d705 {
  strings:
    $key_d705 = { 83 6d [2] f7 75 [2] b0 77 [2] f7 66 [2] b9 6a [2] b5 60 [2] a2 6b [2] b9 25 [2] 84 }

  condition:
    any of them
}