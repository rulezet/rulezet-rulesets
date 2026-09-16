rule TTP_XOR_MULT_DOSStub_d281 {
  strings:
    $key_d281 = { 86 e9 [2] f2 f1 [2] b5 f3 [2] f2 e2 [2] bc ee [2] b0 e4 [2] a7 ef [2] bc a1 [2] 81 }

  condition:
    any of them
}