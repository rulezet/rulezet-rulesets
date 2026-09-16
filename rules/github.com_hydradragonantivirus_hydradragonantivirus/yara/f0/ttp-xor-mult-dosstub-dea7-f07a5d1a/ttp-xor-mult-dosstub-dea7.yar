rule TTP_XOR_MULT_DOSStub_dea7 {
  strings:
    $key_dea7 = { 8a cf [2] fe d7 [2] b9 d5 [2] fe c4 [2] b0 c8 [2] bc c2 [2] ab c9 [2] b0 87 [2] 8d }

  condition:
    any of them
}