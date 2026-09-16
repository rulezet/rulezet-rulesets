rule TTP_XOR_MULT_DOSStub_dbf7 {
  strings:
    $key_dbf7 = { 8f 9f [2] fb 87 [2] bc 85 [2] fb 94 [2] b5 98 [2] b9 92 [2] ae 99 [2] b5 d7 [2] 88 }

  condition:
    any of them
}