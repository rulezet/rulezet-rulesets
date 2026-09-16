rule TTP_XOR_MULT_DOSStub_d27b {
  strings:
    $key_d27b = { 86 13 [2] f2 0b [2] b5 09 [2] f2 18 [2] bc 14 [2] b0 1e [2] a7 15 [2] bc 5b [2] 81 }

  condition:
    any of them
}