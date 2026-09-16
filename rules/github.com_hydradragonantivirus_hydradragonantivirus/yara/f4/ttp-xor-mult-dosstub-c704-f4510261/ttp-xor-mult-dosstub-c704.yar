rule TTP_XOR_MULT_DOSStub_c704 {
  strings:
    $key_c704 = { 93 6c [2] e7 74 [2] a0 76 [2] e7 67 [2] a9 6b [2] a5 61 [2] b2 6a [2] a9 24 [2] 94 }

  condition:
    any of them
}