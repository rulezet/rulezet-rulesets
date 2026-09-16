rule TTP_XOR_MULT_DOSStub_c47e {
  strings:
    $key_c47e = { 90 16 [2] e4 0e [2] a3 0c [2] e4 1d [2] aa 11 [2] a6 1b [2] b1 10 [2] aa 5e [2] 97 }

  condition:
    any of them
}