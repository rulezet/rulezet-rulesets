rule TTP_XOR_MULT_DOSStub_dbc6 {
  strings:
    $key_dbc6 = { 8f ae [2] fb b6 [2] bc b4 [2] fb a5 [2] b5 a9 [2] b9 a3 [2] ae a8 [2] b5 e6 [2] 88 }

  condition:
    any of them
}