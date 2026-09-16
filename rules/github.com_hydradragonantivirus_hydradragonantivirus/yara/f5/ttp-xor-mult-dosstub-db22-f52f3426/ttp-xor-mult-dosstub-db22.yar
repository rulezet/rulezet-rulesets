rule TTP_XOR_MULT_DOSStub_db22 {
  strings:
    $key_db22 = { 8f 4a [2] fb 52 [2] bc 50 [2] fb 41 [2] b5 4d [2] b9 47 [2] ae 4c [2] b5 02 [2] 88 }

  condition:
    any of them
}