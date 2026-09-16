rule TTP_XOR_MULT_DOSStub_d2f7 {
  strings:
    $key_d2f7 = { 86 9f [2] f2 87 [2] b5 85 [2] f2 94 [2] bc 98 [2] b0 92 [2] a7 99 [2] bc d7 [2] 81 }

  condition:
    any of them
}