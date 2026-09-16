rule TTP_XOR_MULT_DOSStub_d709 {
  strings:
    $key_d709 = { 83 61 [2] f7 79 [2] b0 7b [2] f7 6a [2] b9 66 [2] b5 6c [2] a2 67 [2] b9 29 [2] 84 }

  condition:
    any of them
}