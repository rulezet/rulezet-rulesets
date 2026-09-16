rule TTP_XOR_MULT_DOSStub_dea1 {
  strings:
    $key_dea1 = { 8a c9 [2] fe d1 [2] b9 d3 [2] fe c2 [2] b0 ce [2] bc c4 [2] ab cf [2] b0 81 [2] 8d }

  condition:
    any of them
}