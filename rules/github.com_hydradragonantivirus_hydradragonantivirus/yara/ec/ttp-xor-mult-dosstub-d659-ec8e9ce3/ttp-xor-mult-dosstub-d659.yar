rule TTP_XOR_MULT_DOSStub_d659 {
  strings:
    $key_d659 = { 82 31 [2] f6 29 [2] b1 2b [2] f6 3a [2] b8 36 [2] b4 3c [2] a3 37 [2] b8 79 [2] 85 }

  condition:
    any of them
}