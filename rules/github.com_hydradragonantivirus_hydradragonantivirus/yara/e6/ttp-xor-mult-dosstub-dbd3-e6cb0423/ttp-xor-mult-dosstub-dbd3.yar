rule TTP_XOR_MULT_DOSStub_dbd3 {
  strings:
    $key_dbd3 = { 8f bb [2] fb a3 [2] bc a1 [2] fb b0 [2] b5 bc [2] b9 b6 [2] ae bd [2] b5 f3 [2] 88 }

  condition:
    any of them
}