rule TTP_XOR_MULT_DOSStub_d20b {
  strings:
    $key_d20b = { 86 63 [2] f2 7b [2] b5 79 [2] f2 68 [2] bc 64 [2] b0 6e [2] a7 65 [2] bc 2b [2] 81 }

  condition:
    any of them
}