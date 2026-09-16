rule TTP_XOR_MULT_DOSStub_d23b {
  strings:
    $key_d23b = { 86 53 [2] f2 4b [2] b5 49 [2] f2 58 [2] bc 54 [2] b0 5e [2] a7 55 [2] bc 1b [2] 81 }

  condition:
    any of them
}