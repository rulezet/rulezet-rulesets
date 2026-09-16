rule TTP_XOR_MULT_DOSStub_dbd7 {
  strings:
    $key_dbd7 = { 8f bf [2] fb a7 [2] bc a5 [2] fb b4 [2] b5 b8 [2] b9 b2 [2] ae b9 [2] b5 f7 [2] 88 }

  condition:
    any of them
}