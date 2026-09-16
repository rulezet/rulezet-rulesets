rule TTP_XOR_MULT_DOSStub_c634 {
  strings:
    $key_c634 = { 92 5c [2] e6 44 [2] a1 46 [2] e6 57 [2] a8 5b [2] a4 51 [2] b3 5a [2] a8 14 [2] 95 }

  condition:
    any of them
}