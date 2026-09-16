rule TTP_XOR_MULT_DOSStub_c608 {
  strings:
    $key_c608 = { 92 60 [2] e6 78 [2] a1 7a [2] e6 6b [2] a8 67 [2] a4 6d [2] b3 66 [2] a8 28 [2] 95 }

  condition:
    any of them
}