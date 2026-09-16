rule TTP_XOR_MULT_DOSStub_dbb9 {
  strings:
    $key_dbb9 = { 8f d1 [2] fb c9 [2] bc cb [2] fb da [2] b5 d6 [2] b9 dc [2] ae d7 [2] b5 99 [2] 88 }

  condition:
    any of them
}