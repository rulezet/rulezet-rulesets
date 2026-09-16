rule TTP_XOR_MULT_DOSStub_dbd5 {
  strings:
    $key_dbd5 = { 8f bd [2] fb a5 [2] bc a7 [2] fb b6 [2] b5 ba [2] b9 b0 [2] ae bb [2] b5 f5 [2] 88 }

  condition:
    any of them
}