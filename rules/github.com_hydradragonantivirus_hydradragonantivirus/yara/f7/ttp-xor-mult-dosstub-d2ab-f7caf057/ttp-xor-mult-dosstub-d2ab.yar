rule TTP_XOR_MULT_DOSStub_d2ab {
  strings:
    $key_d2ab = { 86 c3 [2] f2 db [2] b5 d9 [2] f2 c8 [2] bc c4 [2] b0 ce [2] a7 c5 [2] bc 8b [2] 81 }

  condition:
    any of them
}