rule TTP_XOR_MULT_DOSStub_c64c {
  strings:
    $key_c64c = { 92 24 [2] e6 3c [2] a1 3e [2] e6 2f [2] a8 23 [2] a4 29 [2] b3 22 [2] a8 6c [2] 95 }

  condition:
    any of them
}