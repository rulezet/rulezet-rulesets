rule TTP_XOR_MULT_DOSStub_db43 {
  strings:
    $key_db43 = { 8f 2b [2] fb 33 [2] bc 31 [2] fb 20 [2] b5 2c [2] b9 26 [2] ae 2d [2] b5 63 [2] 88 }

  condition:
    any of them
}