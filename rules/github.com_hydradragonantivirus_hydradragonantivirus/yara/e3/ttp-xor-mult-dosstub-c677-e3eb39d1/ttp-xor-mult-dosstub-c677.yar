rule TTP_XOR_MULT_DOSStub_c677 {
  strings:
    $key_c677 = { 92 1f [2] e6 07 [2] a1 05 [2] e6 14 [2] a8 18 [2] a4 12 [2] b3 19 [2] a8 57 [2] 95 }

  condition:
    any of them
}