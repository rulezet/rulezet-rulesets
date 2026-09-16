rule TTP_XOR_MULT_DOSStub_dbd6 {
  strings:
    $key_dbd6 = { 8f be [2] fb a6 [2] bc a4 [2] fb b5 [2] b5 b9 [2] b9 b3 [2] ae b8 [2] b5 f6 [2] 88 }

  condition:
    any of them
}