rule TTP_XOR_MULT_DOSStub_c640 {
  strings:
    $key_c640 = { 92 28 [2] e6 30 [2] a1 32 [2] e6 23 [2] a8 2f [2] a4 25 [2] b3 2e [2] a8 60 [2] 95 }

  condition:
    any of them
}