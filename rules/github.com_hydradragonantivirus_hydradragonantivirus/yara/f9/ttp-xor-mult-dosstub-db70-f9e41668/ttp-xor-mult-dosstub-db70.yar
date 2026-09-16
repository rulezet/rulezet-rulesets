rule TTP_XOR_MULT_DOSStub_db70 {
  strings:
    $key_db70 = { 8f 18 [2] fb 00 [2] bc 02 [2] fb 13 [2] b5 1f [2] b9 15 [2] ae 1e [2] b5 50 [2] 88 }

  condition:
    any of them
}