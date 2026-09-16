rule TTP_XOR_MULT_DOSStub_d286 {
  strings:
    $key_d286 = { 86 ee [2] f2 f6 [2] b5 f4 [2] f2 e5 [2] bc e9 [2] b0 e3 [2] a7 e8 [2] bc a6 [2] 81 }

  condition:
    any of them
}