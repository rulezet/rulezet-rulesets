rule TTP_XOR_MULT_DOSStub_c604 {
  strings:
    $key_c604 = { 92 6c [2] e6 74 [2] a1 76 [2] e6 67 [2] a8 6b [2] a4 61 [2] b3 6a [2] a8 24 [2] 95 }

  condition:
    any of them
}