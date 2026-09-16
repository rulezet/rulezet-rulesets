rule TTP_XOR_MULT_DOSStub_dbc1 {
  strings:
    $key_dbc1 = { 8f a9 [2] fb b1 [2] bc b3 [2] fb a2 [2] b5 ae [2] b9 a4 [2] ae af [2] b5 e1 [2] 88 }

  condition:
    any of them
}