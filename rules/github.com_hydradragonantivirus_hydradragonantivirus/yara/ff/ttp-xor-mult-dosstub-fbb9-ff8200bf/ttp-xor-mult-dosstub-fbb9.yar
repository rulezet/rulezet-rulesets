rule TTP_XOR_MULT_DOSStub_fbb9 {
  strings:
    $key_fbb9 = { af d1 [2] db c9 [2] 9c cb [2] db da [2] 95 d6 [2] 99 dc [2] 8e d7 [2] 95 99 [2] a8 }

  condition:
    any of them
}