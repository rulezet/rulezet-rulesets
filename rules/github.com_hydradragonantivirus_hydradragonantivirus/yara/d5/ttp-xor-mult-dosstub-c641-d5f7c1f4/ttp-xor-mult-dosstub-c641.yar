rule TTP_XOR_MULT_DOSStub_c641 {
  strings:
    $key_c641 = { 92 29 [2] e6 31 [2] a1 33 [2] e6 22 [2] a8 2e [2] a4 24 [2] b3 2f [2] a8 61 [2] 95 }

  condition:
    any of them
}