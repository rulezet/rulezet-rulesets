rule TTP_XOR_MULT_DOSStub_d604 {
  strings:
    $key_d604 = { 82 6c [2] f6 74 [2] b1 76 [2] f6 67 [2] b8 6b [2] b4 61 [2] a3 6a [2] b8 24 [2] 85 }

  condition:
    any of them
}