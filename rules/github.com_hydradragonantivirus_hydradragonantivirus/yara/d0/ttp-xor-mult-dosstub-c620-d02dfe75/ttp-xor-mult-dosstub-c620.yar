rule TTP_XOR_MULT_DOSStub_c620 {
  strings:
    $key_c620 = { 92 48 [2] e6 50 [2] a1 52 [2] e6 43 [2] a8 4f [2] a4 45 [2] b3 4e [2] a8 00 [2] 95 }

  condition:
    any of them
}