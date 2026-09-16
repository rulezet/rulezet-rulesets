rule TTP_XOR_MULT_DOSStub_d2a8 {
  strings:
    $key_d2a8 = { 86 c0 [2] f2 d8 [2] b5 da [2] f2 cb [2] bc c7 [2] b0 cd [2] a7 c6 [2] bc 88 [2] 81 }

  condition:
    any of them
}