rule TTP_XOR_MULT_DOSStub_db46 {
  strings:
    $key_db46 = { 8f 2e [2] fb 36 [2] bc 34 [2] fb 25 [2] b5 29 [2] b9 23 [2] ae 28 [2] b5 66 [2] 88 }

  condition:
    any of them
}