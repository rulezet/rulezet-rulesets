rule TTP_XOR_MULT_DOSStub_d230 {
  strings:
    $key_d230 = { 86 58 [2] f2 40 [2] b5 42 [2] f2 53 [2] bc 5f [2] b0 55 [2] a7 5e [2] bc 10 [2] 81 }

  condition:
    any of them
}