rule TTP_XOR_MULT_DOSStub_c46b {
  strings:
    $key_c46b = { 90 03 [2] e4 1b [2] a3 19 [2] e4 08 [2] aa 04 [2] a6 0e [2] b1 05 [2] aa 4b [2] 97 }

  condition:
    any of them
}