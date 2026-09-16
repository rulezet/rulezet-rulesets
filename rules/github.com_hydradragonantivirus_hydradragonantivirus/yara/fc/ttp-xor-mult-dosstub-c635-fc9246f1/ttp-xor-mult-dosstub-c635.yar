rule TTP_XOR_MULT_DOSStub_c635 {
  strings:
    $key_c635 = { 92 5d [2] e6 45 [2] a1 47 [2] e6 56 [2] a8 5a [2] a4 50 [2] b3 5b [2] a8 15 [2] 95 }

  condition:
    any of them
}