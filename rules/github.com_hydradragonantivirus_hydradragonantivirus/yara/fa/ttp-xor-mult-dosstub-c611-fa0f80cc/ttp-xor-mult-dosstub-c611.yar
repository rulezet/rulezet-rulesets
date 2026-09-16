rule TTP_XOR_MULT_DOSStub_c611 {
  strings:
    $key_c611 = { 92 79 [2] e6 61 [2] a1 63 [2] e6 72 [2] a8 7e [2] a4 74 [2] b3 7f [2] a8 31 [2] 95 }

  condition:
    any of them
}