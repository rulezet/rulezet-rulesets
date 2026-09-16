rule TTP_XOR_MULT_DOSStub_dbb4 {
  strings:
    $key_dbb4 = { 8f dc [2] fb c4 [2] bc c6 [2] fb d7 [2] b5 db [2] b9 d1 [2] ae da [2] b5 94 [2] 88 }

  condition:
    any of them
}