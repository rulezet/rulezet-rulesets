rule TTP_XOR_MULT_DOSStub_c66b {
  strings:
    $key_c66b = { 92 03 [2] e6 1b [2] a1 19 [2] e6 08 [2] a8 04 [2] a4 0e [2] b3 05 [2] a8 4b [2] 95 }

  condition:
    any of them
}