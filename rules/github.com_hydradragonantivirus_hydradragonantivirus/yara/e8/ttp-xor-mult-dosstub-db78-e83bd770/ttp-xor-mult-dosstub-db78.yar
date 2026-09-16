rule TTP_XOR_MULT_DOSStub_db78 {
  strings:
    $key_db78 = { 8f 10 [2] fb 08 [2] bc 0a [2] fb 1b [2] b5 17 [2] b9 1d [2] ae 16 [2] b5 58 [2] 88 }

  condition:
    any of them
}