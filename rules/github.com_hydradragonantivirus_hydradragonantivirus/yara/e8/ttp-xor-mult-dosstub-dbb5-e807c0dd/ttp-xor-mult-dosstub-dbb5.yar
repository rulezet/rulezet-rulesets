rule TTP_XOR_MULT_DOSStub_dbb5 {
  strings:
    $key_dbb5 = { 8f dd [2] fb c5 [2] bc c7 [2] fb d6 [2] b5 da [2] b9 d0 [2] ae db [2] b5 95 [2] 88 }

  condition:
    any of them
}