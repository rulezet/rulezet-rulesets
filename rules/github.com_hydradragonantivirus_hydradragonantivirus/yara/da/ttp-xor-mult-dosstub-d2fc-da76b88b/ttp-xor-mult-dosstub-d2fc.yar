rule TTP_XOR_MULT_DOSStub_d2fc {
  strings:
    $key_d2fc = { 86 94 [2] f2 8c [2] b5 8e [2] f2 9f [2] bc 93 [2] b0 99 [2] a7 92 [2] bc dc [2] 81 }

  condition:
    any of them
}