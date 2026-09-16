rule TTP_XOR_MULT_DOSStub_d613 {
  strings:
    $key_d613 = { 82 7b [2] f6 63 [2] b1 61 [2] f6 70 [2] b8 7c [2] b4 76 [2] a3 7d [2] b8 33 [2] 85 }

  condition:
    any of them
}