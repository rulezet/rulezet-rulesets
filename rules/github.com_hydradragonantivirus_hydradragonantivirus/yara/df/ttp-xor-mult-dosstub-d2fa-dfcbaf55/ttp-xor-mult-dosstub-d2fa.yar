rule TTP_XOR_MULT_DOSStub_d2fa {
  strings:
    $key_d2fa = { 86 92 [2] f2 8a [2] b5 88 [2] f2 99 [2] bc 95 [2] b0 9f [2] a7 94 [2] bc da [2] 81 }

  condition:
    any of them
}