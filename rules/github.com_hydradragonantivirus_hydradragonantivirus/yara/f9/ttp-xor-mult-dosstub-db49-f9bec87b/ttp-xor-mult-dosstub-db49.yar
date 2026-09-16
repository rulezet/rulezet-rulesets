rule TTP_XOR_MULT_DOSStub_db49 {
  strings:
    $key_db49 = { 8f 21 [2] fb 39 [2] bc 3b [2] fb 2a [2] b5 26 [2] b9 2c [2] ae 27 [2] b5 69 [2] 88 }

  condition:
    any of them
}