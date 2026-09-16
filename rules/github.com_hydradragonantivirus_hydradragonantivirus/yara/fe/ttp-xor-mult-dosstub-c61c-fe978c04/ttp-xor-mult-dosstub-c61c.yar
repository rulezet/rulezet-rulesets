rule TTP_XOR_MULT_DOSStub_c61c {
  strings:
    $key_c61c = { 92 74 [2] e6 6c [2] a1 6e [2] e6 7f [2] a8 73 [2] a4 79 [2] b3 72 [2] a8 3c [2] 95 }

  condition:
    any of them
}