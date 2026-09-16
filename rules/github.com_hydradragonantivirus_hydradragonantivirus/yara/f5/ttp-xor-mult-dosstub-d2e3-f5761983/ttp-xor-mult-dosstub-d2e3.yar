rule TTP_XOR_MULT_DOSStub_d2e3 {
  strings:
    $key_d2e3 = { 86 8b [2] f2 93 [2] b5 91 [2] f2 80 [2] bc 8c [2] b0 86 [2] a7 8d [2] bc c3 [2] 81 }

  condition:
    any of them
}