rule TTP_XOR_MULT_DOSStub_d226 {
  strings:
    $key_d226 = { 86 4e [2] f2 56 [2] b5 54 [2] f2 45 [2] bc 49 [2] b0 43 [2] a7 48 [2] bc 06 [2] 81 }

  condition:
    any of them
}