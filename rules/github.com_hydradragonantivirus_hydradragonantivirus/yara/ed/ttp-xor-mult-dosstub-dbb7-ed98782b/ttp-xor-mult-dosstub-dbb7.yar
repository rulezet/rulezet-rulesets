rule TTP_XOR_MULT_DOSStub_dbb7 {
  strings:
    $key_dbb7 = { 8f df [2] fb c7 [2] bc c5 [2] fb d4 [2] b5 d8 [2] b9 d2 [2] ae d9 [2] b5 97 [2] 88 }

  condition:
    any of them
}